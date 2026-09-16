rule TTP_XOR_MULT_DOSStub_657d {
  strings:
    $key_657d = { 31 15 [2] 45 0d [2] 02 0f [2] 45 1e [2] 0b 12 [2] 07 18 [2] 10 13 [2] 0b 5d [2] 36 }

  condition:
    any of them
}