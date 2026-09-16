rule TTP_XOR_MULT_DOSStub_cb44 {
  strings:
    $key_cb44 = { 9f 2c [2] eb 34 [2] ac 36 [2] eb 27 [2] a5 2b [2] a9 21 [2] be 2a [2] a5 64 [2] 98 }

  condition:
    any of them
}