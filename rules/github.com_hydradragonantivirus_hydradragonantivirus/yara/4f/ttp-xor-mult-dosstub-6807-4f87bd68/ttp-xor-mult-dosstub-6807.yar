rule TTP_XOR_MULT_DOSStub_6807 {
  strings:
    $key_6807 = { 3c 6f [2] 48 77 [2] 0f 75 [2] 48 64 [2] 06 68 [2] 0a 62 [2] 1d 69 [2] 06 27 [2] 3b }

  condition:
    any of them
}