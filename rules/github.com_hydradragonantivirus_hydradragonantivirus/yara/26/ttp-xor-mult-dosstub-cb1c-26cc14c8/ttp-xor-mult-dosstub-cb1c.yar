rule TTP_XOR_MULT_DOSStub_cb1c {
  strings:
    $key_cb1c = { 9f 74 [2] eb 6c [2] ac 6e [2] eb 7f [2] a5 73 [2] a9 79 [2] be 72 [2] a5 3c [2] 98 }

  condition:
    any of them
}