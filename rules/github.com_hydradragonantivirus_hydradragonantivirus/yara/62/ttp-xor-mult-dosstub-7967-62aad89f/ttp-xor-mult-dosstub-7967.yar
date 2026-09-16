rule TTP_XOR_MULT_DOSStub_7967 {
  strings:
    $key_7967 = { 2d 0f [2] 59 17 [2] 1e 15 [2] 59 04 [2] 17 08 [2] 1b 02 [2] 0c 09 [2] 17 47 [2] 2a }

  condition:
    any of them
}