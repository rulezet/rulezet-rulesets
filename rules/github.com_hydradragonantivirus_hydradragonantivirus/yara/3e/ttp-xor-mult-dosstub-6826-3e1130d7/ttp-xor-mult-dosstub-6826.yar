rule TTP_XOR_MULT_DOSStub_6826 {
  strings:
    $key_6826 = { 3c 4e [2] 48 56 [2] 0f 54 [2] 48 45 [2] 06 49 [2] 0a 43 [2] 1d 48 [2] 06 06 [2] 3b }

  condition:
    any of them
}