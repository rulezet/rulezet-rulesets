rule TTP_XOR_MULT_DOSStub_cb79 {
  strings:
    $key_cb79 = { 9f 11 [2] eb 09 [2] ac 0b [2] eb 1a [2] a5 16 [2] a9 1c [2] be 17 [2] a5 59 [2] 98 }

  condition:
    any of them
}