rule TTP_XOR_MULT_DOSStub_cbf6 {
  strings:
    $key_cbf6 = { 9f 9e [2] eb 86 [2] ac 84 [2] eb 95 [2] a5 99 [2] a9 93 [2] be 98 [2] a5 d6 [2] 98 }

  condition:
    any of them
}