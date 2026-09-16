rule TTP_XOR_MULT_DOSStub_cb47 {
  strings:
    $key_cb47 = { 9f 2f [2] eb 37 [2] ac 35 [2] eb 24 [2] a5 28 [2] a9 22 [2] be 29 [2] a5 67 [2] 98 }

  condition:
    any of them
}