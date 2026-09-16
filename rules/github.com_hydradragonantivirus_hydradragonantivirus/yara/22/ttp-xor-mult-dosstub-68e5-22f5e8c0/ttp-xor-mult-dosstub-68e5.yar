rule TTP_XOR_MULT_DOSStub_68e5 {
  strings:
    $key_68e5 = { 3c 8d [2] 48 95 [2] 0f 97 [2] 48 86 [2] 06 8a [2] 0a 80 [2] 1d 8b [2] 06 c5 [2] 3b }

  condition:
    any of them
}