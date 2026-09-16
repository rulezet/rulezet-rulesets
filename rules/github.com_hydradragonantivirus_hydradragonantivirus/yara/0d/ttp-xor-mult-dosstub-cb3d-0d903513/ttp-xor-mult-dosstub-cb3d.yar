rule TTP_XOR_MULT_DOSStub_cb3d {
  strings:
    $key_cb3d = { 9f 55 [2] eb 4d [2] ac 4f [2] eb 5e [2] a5 52 [2] a9 58 [2] be 53 [2] a5 1d [2] 98 }

  condition:
    any of them
}