rule TTP_XOR_MULT_DOSStub_cbe0 {
  strings:
    $key_cbe0 = { 9f 88 [2] eb 90 [2] ac 92 [2] eb 83 [2] a5 8f [2] a9 85 [2] be 8e [2] a5 c0 [2] 98 }

  condition:
    any of them
}