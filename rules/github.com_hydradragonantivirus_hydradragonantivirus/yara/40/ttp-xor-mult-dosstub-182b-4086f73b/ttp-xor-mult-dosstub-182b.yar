rule TTP_XOR_MULT_DOSStub_182b {
  strings:
    $key_182b = { 4c 43 [2] 38 5b [2] 7f 59 [2] 38 48 [2] 76 44 [2] 7a 4e [2] 6d 45 [2] 76 0b [2] 4b }

  condition:
    any of them
}