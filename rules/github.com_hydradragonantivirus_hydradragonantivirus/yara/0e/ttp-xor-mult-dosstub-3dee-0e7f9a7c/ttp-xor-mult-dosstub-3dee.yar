rule TTP_XOR_MULT_DOSStub_3dee {
  strings:
    $key_3dee = { 69 86 [2] 1d 9e [2] 5a 9c [2] 1d 8d [2] 53 81 [2] 5f 8b [2] 48 80 [2] 53 ce [2] 6e }

  condition:
    any of them
}