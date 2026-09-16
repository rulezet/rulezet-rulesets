rule TTP_XOR_MULT_DOSStub_cb2a {
  strings:
    $key_cb2a = { 9f 42 [2] eb 5a [2] ac 58 [2] eb 49 [2] a5 45 [2] a9 4f [2] be 44 [2] a5 0a [2] 98 }

  condition:
    any of them
}