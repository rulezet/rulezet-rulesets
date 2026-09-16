rule TTP_XOR_MULT_DOSStub_cb4e {
  strings:
    $key_cb4e = { 9f 26 [2] eb 3e [2] ac 3c [2] eb 2d [2] a5 21 [2] a9 2b [2] be 20 [2] a5 6e [2] 98 }

  condition:
    any of them
}