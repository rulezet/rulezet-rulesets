rule TTP_XOR_MULT_DOSStub_cb5c {
  strings:
    $key_cb5c = { 9f 34 [2] eb 2c [2] ac 2e [2] eb 3f [2] a5 33 [2] a9 39 [2] be 32 [2] a5 7c [2] 98 }

  condition:
    any of them
}