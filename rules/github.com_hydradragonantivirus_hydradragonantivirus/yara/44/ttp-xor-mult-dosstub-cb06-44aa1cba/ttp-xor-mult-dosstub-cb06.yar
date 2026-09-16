rule TTP_XOR_MULT_DOSStub_cb06 {
  strings:
    $key_cb06 = { 9f 6e [2] eb 76 [2] ac 74 [2] eb 65 [2] a5 69 [2] a9 63 [2] be 68 [2] a5 26 [2] 98 }

  condition:
    any of them
}