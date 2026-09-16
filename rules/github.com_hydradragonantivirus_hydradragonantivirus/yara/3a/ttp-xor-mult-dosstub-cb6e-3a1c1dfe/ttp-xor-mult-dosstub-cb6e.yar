rule TTP_XOR_MULT_DOSStub_cb6e {
  strings:
    $key_cb6e = { 9f 06 [2] eb 1e [2] ac 1c [2] eb 0d [2] a5 01 [2] a9 0b [2] be 00 [2] a5 4e [2] 98 }

  condition:
    any of them
}