rule TTP_XOR_MULT_DOSStub_f84b {
  strings:
    $key_f84b = { ac 23 [2] d8 3b [2] 9f 39 [2] d8 28 [2] 96 24 [2] 9a 2e [2] 8d 25 [2] 96 6b [2] ab }

  condition:
    any of them
}