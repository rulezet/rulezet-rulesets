rule TTP_XOR_MULT_DOSStub_cbde {
  strings:
    $key_cbde = { 9f b6 [2] eb ae [2] ac ac [2] eb bd [2] a5 b1 [2] a9 bb [2] be b0 [2] a5 fe [2] 98 }

  condition:
    any of them
}