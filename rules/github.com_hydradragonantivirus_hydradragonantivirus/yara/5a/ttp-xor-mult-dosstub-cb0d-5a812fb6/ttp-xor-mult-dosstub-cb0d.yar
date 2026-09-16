rule TTP_XOR_MULT_DOSStub_cb0d {
  strings:
    $key_cb0d = { 9f 65 [2] eb 7d [2] ac 7f [2] eb 6e [2] a5 62 [2] a9 68 [2] be 63 [2] a5 2d [2] 98 }

  condition:
    any of them
}