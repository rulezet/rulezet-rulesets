rule TTP_XOR_MULT_DOSStub_cb36 {
  strings:
    $key_cb36 = { 9f 5e [2] eb 46 [2] ac 44 [2] eb 55 [2] a5 59 [2] a9 53 [2] be 58 [2] a5 16 [2] 98 }

  condition:
    any of them
}