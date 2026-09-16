rule TTP_XOR_MULT_DOSStub_cb00 {
  strings:
    $key_cb00 = { 9f 68 [2] eb 70 [2] ac 72 [2] eb 63 [2] a5 6f [2] a9 65 [2] be 6e [2] a5 20 [2] 98 }

  condition:
    any of them
}