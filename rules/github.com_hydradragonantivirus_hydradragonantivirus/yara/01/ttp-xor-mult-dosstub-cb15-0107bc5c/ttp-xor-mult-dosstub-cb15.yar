rule TTP_XOR_MULT_DOSStub_cb15 {
  strings:
    $key_cb15 = { 9f 7d [2] eb 65 [2] ac 67 [2] eb 76 [2] a5 7a [2] a9 70 [2] be 7b [2] a5 35 [2] 98 }

  condition:
    any of them
}