rule TTP_XOR_MULT_DOSStub_cbe5 {
  strings:
    $key_cbe5 = { 9f 8d [2] eb 95 [2] ac 97 [2] eb 86 [2] a5 8a [2] a9 80 [2] be 8b [2] a5 c5 [2] 98 }

  condition:
    any of them
}