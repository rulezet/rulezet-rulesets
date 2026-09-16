rule TTP_XOR_MULT_DOSStub_2a3b {
  strings:
    $key_2a3b = { 7e 53 [2] 0a 4b [2] 4d 49 [2] 0a 58 [2] 44 54 [2] 48 5e [2] 5f 55 [2] 44 1b [2] 79 }

  condition:
    any of them
}