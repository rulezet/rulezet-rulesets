rule TTP_XOR_MULT_DOSStub_cb61 {
  strings:
    $key_cb61 = { 9f 09 [2] eb 11 [2] ac 13 [2] eb 02 [2] a5 0e [2] a9 04 [2] be 0f [2] a5 41 [2] 98 }

  condition:
    any of them
}