rule TTP_XOR_MULT_DOSStub_cb4c {
  strings:
    $key_cb4c = { 9f 24 [2] eb 3c [2] ac 3e [2] eb 2f [2] a5 23 [2] a9 29 [2] be 22 [2] a5 6c [2] 98 }

  condition:
    any of them
}