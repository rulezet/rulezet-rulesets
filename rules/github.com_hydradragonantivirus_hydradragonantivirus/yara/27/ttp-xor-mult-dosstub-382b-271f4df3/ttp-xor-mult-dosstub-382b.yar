rule TTP_XOR_MULT_DOSStub_382b {
  strings:
    $key_382b = { 6c 43 [2] 18 5b [2] 5f 59 [2] 18 48 [2] 56 44 [2] 5a 4e [2] 4d 45 [2] 56 0b [2] 6b }

  condition:
    any of them
}