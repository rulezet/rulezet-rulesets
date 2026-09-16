rule TTP_XOR_MULT_DOSStub_cb5e {
  strings:
    $key_cb5e = { 9f 36 [2] eb 2e [2] ac 2c [2] eb 3d [2] a5 31 [2] a9 3b [2] be 30 [2] a5 7e [2] 98 }

  condition:
    any of them
}