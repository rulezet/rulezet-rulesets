rule TTP_XOR_MULT_DOSStub_cb12 {
  strings:
    $key_cb12 = { 9f 7a [2] eb 62 [2] ac 60 [2] eb 71 [2] a5 7d [2] a9 77 [2] be 7c [2] a5 32 [2] 98 }

  condition:
    any of them
}