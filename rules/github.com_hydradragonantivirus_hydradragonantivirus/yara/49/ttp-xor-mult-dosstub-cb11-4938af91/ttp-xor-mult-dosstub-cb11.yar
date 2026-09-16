rule TTP_XOR_MULT_DOSStub_cb11 {
  strings:
    $key_cb11 = { 9f 79 [2] eb 61 [2] ac 63 [2] eb 72 [2] a5 7e [2] a9 74 [2] be 7f [2] a5 31 [2] 98 }

  condition:
    any of them
}