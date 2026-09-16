rule TTP_XOR_MULT_DOSStub_4df2 {
  strings:
    $key_4df2 = { 19 9a [2] 6d 82 [2] 2a 80 [2] 6d 91 [2] 23 9d [2] 2f 97 [2] 38 9c [2] 23 d2 [2] 1e }

  condition:
    any of them
}