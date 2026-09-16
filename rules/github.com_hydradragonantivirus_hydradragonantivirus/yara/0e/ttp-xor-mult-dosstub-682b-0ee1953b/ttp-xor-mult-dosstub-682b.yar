rule TTP_XOR_MULT_DOSStub_682b {
  strings:
    $key_682b = { 3c 43 [2] 48 5b [2] 0f 59 [2] 48 48 [2] 06 44 [2] 0a 4e [2] 1d 45 [2] 06 0b [2] 3b }

  condition:
    any of them
}