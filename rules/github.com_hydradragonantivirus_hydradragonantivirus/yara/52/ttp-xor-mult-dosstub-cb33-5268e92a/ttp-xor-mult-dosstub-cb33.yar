rule TTP_XOR_MULT_DOSStub_cb33 {
  strings:
    $key_cb33 = { 9f 5b [2] eb 43 [2] ac 41 [2] eb 50 [2] a5 5c [2] a9 56 [2] be 5d [2] a5 13 [2] 98 }

  condition:
    any of them
}