rule TTP_XOR_MULT_DOSStub_cbe9 {
  strings:
    $key_cbe9 = { 9f 81 [2] eb 99 [2] ac 9b [2] eb 8a [2] a5 86 [2] a9 8c [2] be 87 [2] a5 c9 [2] 98 }

  condition:
    any of them
}