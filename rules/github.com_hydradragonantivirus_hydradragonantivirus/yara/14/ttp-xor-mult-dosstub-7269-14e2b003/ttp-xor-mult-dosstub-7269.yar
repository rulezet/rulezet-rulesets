rule TTP_XOR_MULT_DOSStub_7269 {
  strings:
    $key_7269 = { 26 01 [2] 52 19 [2] 15 1b [2] 52 0a [2] 1c 06 [2] 10 0c [2] 07 07 [2] 1c 49 [2] 21 }

  condition:
    any of them
}