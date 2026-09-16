rule TTP_XOR_MULT_DOSStub_cb13 {
  strings:
    $key_cb13 = { 9f 7b [2] eb 63 [2] ac 61 [2] eb 70 [2] a5 7c [2] a9 76 [2] be 7d [2] a5 33 [2] 98 }

  condition:
    any of them
}