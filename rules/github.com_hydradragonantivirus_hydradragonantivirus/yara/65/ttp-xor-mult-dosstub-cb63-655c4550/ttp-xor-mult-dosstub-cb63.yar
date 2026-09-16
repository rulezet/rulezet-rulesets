rule TTP_XOR_MULT_DOSStub_cb63 {
  strings:
    $key_cb63 = { 9f 0b [2] eb 13 [2] ac 11 [2] eb 00 [2] a5 0c [2] a9 06 [2] be 0d [2] a5 43 [2] 98 }

  condition:
    any of them
}