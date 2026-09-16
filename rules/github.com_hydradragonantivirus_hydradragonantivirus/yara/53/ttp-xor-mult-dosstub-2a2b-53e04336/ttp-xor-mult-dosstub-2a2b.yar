rule TTP_XOR_MULT_DOSStub_2a2b {
  strings:
    $key_2a2b = { 7e 43 [2] 0a 5b [2] 4d 59 [2] 0a 48 [2] 44 44 [2] 48 4e [2] 5f 45 [2] 44 0b [2] 79 }

  condition:
    any of them
}