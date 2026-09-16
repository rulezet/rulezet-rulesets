rule TTP_XOR_MULT_DOSStub_242b {
  strings:
    $key_242b = { 70 43 [2] 04 5b [2] 43 59 [2] 04 48 [2] 4a 44 [2] 46 4e [2] 51 45 [2] 4a 0b [2] 77 }

  condition:
    any of them
}