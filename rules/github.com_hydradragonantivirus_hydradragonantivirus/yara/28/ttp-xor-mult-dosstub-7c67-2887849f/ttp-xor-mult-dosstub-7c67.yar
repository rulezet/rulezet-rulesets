rule TTP_XOR_MULT_DOSStub_7c67 {
  strings:
    $key_7c67 = { 28 0f [2] 5c 17 [2] 1b 15 [2] 5c 04 [2] 12 08 [2] 1e 02 [2] 09 09 [2] 12 47 [2] 2f }

  condition:
    any of them
}