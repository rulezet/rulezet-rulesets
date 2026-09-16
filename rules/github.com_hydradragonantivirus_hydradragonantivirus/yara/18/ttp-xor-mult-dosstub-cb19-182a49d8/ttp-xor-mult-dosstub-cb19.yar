rule TTP_XOR_MULT_DOSStub_cb19 {
  strings:
    $key_cb19 = { 9f 71 [2] eb 69 [2] ac 6b [2] eb 7a [2] a5 76 [2] a9 7c [2] be 77 [2] a5 39 [2] 98 }

  condition:
    any of them
}