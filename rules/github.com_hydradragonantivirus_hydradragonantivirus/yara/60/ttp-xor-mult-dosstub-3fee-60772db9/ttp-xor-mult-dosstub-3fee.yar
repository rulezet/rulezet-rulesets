rule TTP_XOR_MULT_DOSStub_3fee {
  strings:
    $key_3fee = { 6b 86 [2] 1f 9e [2] 58 9c [2] 1f 8d [2] 51 81 [2] 5d 8b [2] 4a 80 [2] 51 ce [2] 6c }

  condition:
    any of them
}