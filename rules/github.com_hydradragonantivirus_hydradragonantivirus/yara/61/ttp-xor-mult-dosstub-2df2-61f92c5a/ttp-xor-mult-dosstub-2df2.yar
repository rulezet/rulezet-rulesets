rule TTP_XOR_MULT_DOSStub_2df2 {
  strings:
    $key_2df2 = { 79 9a [2] 0d 82 [2] 4a 80 [2] 0d 91 [2] 43 9d [2] 4f 97 [2] 58 9c [2] 43 d2 [2] 7e }

  condition:
    any of them
}