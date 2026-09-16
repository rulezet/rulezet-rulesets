rule TTP_XOR_MULT_DOSStub_2dee {
  strings:
    $key_2dee = { 79 86 [2] 0d 9e [2] 4a 9c [2] 0d 8d [2] 43 81 [2] 4f 8b [2] 58 80 [2] 43 ce [2] 7e }

  condition:
    any of them
}