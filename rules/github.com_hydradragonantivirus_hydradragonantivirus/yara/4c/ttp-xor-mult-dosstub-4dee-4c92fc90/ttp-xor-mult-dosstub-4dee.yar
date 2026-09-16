rule TTP_XOR_MULT_DOSStub_4dee {
  strings:
    $key_4dee = { 19 86 [2] 6d 9e [2] 2a 9c [2] 6d 8d [2] 23 81 [2] 2f 8b [2] 38 80 [2] 23 ce [2] 1e }

  condition:
    any of them
}