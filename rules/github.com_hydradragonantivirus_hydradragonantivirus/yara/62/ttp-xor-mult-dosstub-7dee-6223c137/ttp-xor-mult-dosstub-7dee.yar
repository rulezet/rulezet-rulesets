rule TTP_XOR_MULT_DOSStub_7dee {
  strings:
    $key_7dee = { 29 86 [2] 5d 9e [2] 1a 9c [2] 5d 8d [2] 13 81 [2] 1f 8b [2] 08 80 [2] 13 ce [2] 2e }

  condition:
    any of them
}