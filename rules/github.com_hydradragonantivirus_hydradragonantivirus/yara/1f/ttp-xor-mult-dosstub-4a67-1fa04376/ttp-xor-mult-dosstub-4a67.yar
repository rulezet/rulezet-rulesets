rule TTP_XOR_MULT_DOSStub_4a67 {
  strings:
    $key_4a67 = { 1e 0f [2] 6a 17 [2] 2d 15 [2] 6a 04 [2] 24 08 [2] 28 02 [2] 3f 09 [2] 24 47 [2] 19 }

  condition:
    any of them
}