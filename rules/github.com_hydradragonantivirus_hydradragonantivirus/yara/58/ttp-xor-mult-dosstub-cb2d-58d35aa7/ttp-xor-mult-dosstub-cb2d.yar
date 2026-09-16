rule TTP_XOR_MULT_DOSStub_cb2d {
  strings:
    $key_cb2d = { 9f 45 [2] eb 5d [2] ac 5f [2] eb 4e [2] a5 42 [2] a9 48 [2] be 43 [2] a5 0d [2] 98 }

  condition:
    any of them
}