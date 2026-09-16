rule TTP_XOR_MULT_DOSStub_cb01 {
  strings:
    $key_cb01 = { 9f 69 [2] eb 71 [2] ac 73 [2] eb 62 [2] a5 6e [2] a9 64 [2] be 6f [2] a5 21 [2] 98 }

  condition:
    any of them
}