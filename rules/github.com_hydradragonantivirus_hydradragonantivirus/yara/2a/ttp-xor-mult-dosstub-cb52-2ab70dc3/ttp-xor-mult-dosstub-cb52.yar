rule TTP_XOR_MULT_DOSStub_cb52 {
  strings:
    $key_cb52 = { 9f 3a [2] eb 22 [2] ac 20 [2] eb 31 [2] a5 3d [2] a9 37 [2] be 3c [2] a5 72 [2] 98 }

  condition:
    any of them
}