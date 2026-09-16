rule TTP_XOR_MULT_DOSStub_68fc {
  strings:
    $key_68fc = { 3c 94 [2] 48 8c [2] 0f 8e [2] 48 9f [2] 06 93 [2] 0a 99 [2] 1d 92 [2] 06 dc [2] 3b }

  condition:
    any of them
}