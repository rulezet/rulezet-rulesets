rule TTP_XOR_MULT_DOSStub_cb54 {
  strings:
    $key_cb54 = { 9f 3c [2] eb 24 [2] ac 26 [2] eb 37 [2] a5 3b [2] a9 31 [2] be 3a [2] a5 74 [2] 98 }

  condition:
    any of them
}