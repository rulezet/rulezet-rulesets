rule TTP_XOR_MULT_DOSStub_052b {
  strings:
    $key_052b = { 51 43 [2] 25 5b [2] 62 59 [2] 25 48 [2] 6b 44 [2] 67 4e [2] 70 45 [2] 6b 0b [2] 56 }

  condition:
    any of them
}