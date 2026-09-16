rule TTP_XOR_MULT_DOSStub_cb18 {
  strings:
    $key_cb18 = { 9f 70 [2] eb 68 [2] ac 6a [2] eb 7b [2] a5 77 [2] a9 7d [2] be 76 [2] a5 38 [2] 98 }

  condition:
    any of them
}