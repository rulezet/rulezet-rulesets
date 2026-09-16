rule TTP_XOR_MULT_DOSStub_cb5d {
  strings:
    $key_cb5d = { 9f 35 [2] eb 2d [2] ac 2f [2] eb 3e [2] a5 32 [2] a9 38 [2] be 33 [2] a5 7d [2] 98 }

  condition:
    any of them
}