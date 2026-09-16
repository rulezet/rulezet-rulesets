rule TTP_XOR_MULT_DOSStub_cb42 {
  strings:
    $key_cb42 = { 9f 2a [2] eb 32 [2] ac 30 [2] eb 21 [2] a5 2d [2] a9 27 [2] be 2c [2] a5 62 [2] 98 }

  condition:
    any of them
}