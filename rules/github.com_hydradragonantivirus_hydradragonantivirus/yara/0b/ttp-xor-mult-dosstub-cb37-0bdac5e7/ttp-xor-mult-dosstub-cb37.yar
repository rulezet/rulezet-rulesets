rule TTP_XOR_MULT_DOSStub_cb37 {
  strings:
    $key_cb37 = { 9f 5f [2] eb 47 [2] ac 45 [2] eb 54 [2] a5 58 [2] a9 52 [2] be 59 [2] a5 17 [2] 98 }

  condition:
    any of them
}