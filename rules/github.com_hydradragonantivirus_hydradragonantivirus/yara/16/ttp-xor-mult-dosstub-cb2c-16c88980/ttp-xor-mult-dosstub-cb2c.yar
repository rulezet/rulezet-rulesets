rule TTP_XOR_MULT_DOSStub_cb2c {
  strings:
    $key_cb2c = { 9f 44 [2] eb 5c [2] ac 5e [2] eb 4f [2] a5 43 [2] a9 49 [2] be 42 [2] a5 0c [2] 98 }

  condition:
    any of them
}