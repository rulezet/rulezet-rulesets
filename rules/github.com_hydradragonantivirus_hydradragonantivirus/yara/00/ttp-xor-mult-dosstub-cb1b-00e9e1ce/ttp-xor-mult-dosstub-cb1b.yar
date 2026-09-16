rule TTP_XOR_MULT_DOSStub_cb1b {
  strings:
    $key_cb1b = { 9f 73 [2] eb 6b [2] ac 69 [2] eb 78 [2] a5 74 [2] a9 7e [2] be 75 [2] a5 3b [2] 98 }

  condition:
    any of them
}