rule TTP_XOR_MULT_DOSStub_cb1a {
  strings:
    $key_cb1a = { 9f 72 [2] eb 6a [2] ac 68 [2] eb 79 [2] a5 75 [2] a9 7f [2] be 74 [2] a5 3a [2] 98 }

  condition:
    any of them
}