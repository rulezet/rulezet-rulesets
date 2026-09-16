rule TTP_XOR_MULT_DOSStub_cbf7 {
  strings:
    $key_cbf7 = { 9f 9f [2] eb 87 [2] ac 85 [2] eb 94 [2] a5 98 [2] a9 92 [2] be 99 [2] a5 d7 [2] 98 }

  condition:
    any of them
}