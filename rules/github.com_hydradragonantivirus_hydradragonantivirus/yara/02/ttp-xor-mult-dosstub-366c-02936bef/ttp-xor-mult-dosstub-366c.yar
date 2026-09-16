rule TTP_XOR_MULT_DOSStub_366c {
  strings:
    $key_366c = { 62 04 [2] 16 1c [2] 51 1e [2] 16 0f [2] 58 03 [2] 54 09 [2] 43 02 [2] 58 4c [2] 65 }

  condition:
    any of them
}