rule TTP_XOR_MULT_DOSStub_cb46 {
  strings:
    $key_cb46 = { 9f 2e [2] eb 36 [2] ac 34 [2] eb 25 [2] a5 29 [2] a9 23 [2] be 28 [2] a5 66 [2] 98 }

  condition:
    any of them
}