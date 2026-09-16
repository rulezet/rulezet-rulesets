rule TTP_XOR_MULT_DOSStub_cb55 {
  strings:
    $key_cb55 = { 9f 3d [2] eb 25 [2] ac 27 [2] eb 36 [2] a5 3a [2] a9 30 [2] be 3b [2] a5 75 [2] 98 }

  condition:
    any of them
}