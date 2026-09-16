rule TTP_XOR_MULT_DOSStub_562b {
  strings:
    $key_562b = { 02 43 [2] 76 5b [2] 31 59 [2] 76 48 [2] 38 44 [2] 34 4e [2] 23 45 [2] 38 0b [2] 05 }

  condition:
    any of them
}