rule TTP_XOR_MULT_DOSStub_cb5a {
  strings:
    $key_cb5a = { 9f 32 [2] eb 2a [2] ac 28 [2] eb 39 [2] a5 35 [2] a9 3f [2] be 34 [2] a5 7a [2] 98 }

  condition:
    any of them
}