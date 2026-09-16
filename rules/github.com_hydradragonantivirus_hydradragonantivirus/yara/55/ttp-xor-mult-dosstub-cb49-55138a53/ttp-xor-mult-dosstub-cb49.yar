rule TTP_XOR_MULT_DOSStub_cb49 {
  strings:
    $key_cb49 = { 9f 21 [2] eb 39 [2] ac 3b [2] eb 2a [2] a5 26 [2] a9 2c [2] be 27 [2] a5 69 [2] 98 }

  condition:
    any of them
}