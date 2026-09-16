rule TTP_XOR_MULT_DOSStub_6aee {
  strings:
    $key_6aee = { 3e 86 [2] 4a 9e [2] 0d 9c [2] 4a 8d [2] 04 81 [2] 08 8b [2] 1f 80 [2] 04 ce [2] 39 }

  condition:
    any of them
}