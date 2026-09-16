rule TTP_XOR_MULT_DOSStub_cbe2 {
  strings:
    $key_cbe2 = { 9f 8a [2] eb 92 [2] ac 90 [2] eb 81 [2] a5 8d [2] a9 87 [2] be 8c [2] a5 c2 [2] 98 }

  condition:
    any of them
}