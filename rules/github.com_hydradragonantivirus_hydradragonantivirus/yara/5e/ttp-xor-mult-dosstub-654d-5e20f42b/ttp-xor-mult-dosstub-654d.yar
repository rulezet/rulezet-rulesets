rule TTP_XOR_MULT_DOSStub_654d {
  strings:
    $key_654d = { 31 25 [2] 45 3d [2] 02 3f [2] 45 2e [2] 0b 22 [2] 07 28 [2] 10 23 [2] 0b 6d [2] 36 }

  condition:
    any of them
}