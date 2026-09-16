rule TTP_XOR_MULT_DOSStub_3df2 {
  strings:
    $key_3df2 = { 69 9a [2] 1d 82 [2] 5a 80 [2] 1d 91 [2] 53 9d [2] 5f 97 [2] 48 9c [2] 53 d2 [2] 6e }

  condition:
    any of them
}