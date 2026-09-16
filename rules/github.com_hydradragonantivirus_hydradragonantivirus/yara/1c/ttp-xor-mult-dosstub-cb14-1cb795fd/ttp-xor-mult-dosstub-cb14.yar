rule TTP_XOR_MULT_DOSStub_cb14 {
  strings:
    $key_cb14 = { 9f 7c [2] eb 64 [2] ac 66 [2] eb 77 [2] a5 7b [2] a9 71 [2] be 7a [2] a5 34 [2] 98 }

  condition:
    any of them
}