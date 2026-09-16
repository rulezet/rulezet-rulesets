rule TTP_XOR_MULT_DOSStub_0963 {
  strings:
    $key_0963 = { 5d 0b [2] 29 13 [2] 6e 11 [2] 29 00 [2] 67 0c [2] 6b 06 [2] 7c 0d [2] 67 43 [2] 5a }

  condition:
    any of them
}