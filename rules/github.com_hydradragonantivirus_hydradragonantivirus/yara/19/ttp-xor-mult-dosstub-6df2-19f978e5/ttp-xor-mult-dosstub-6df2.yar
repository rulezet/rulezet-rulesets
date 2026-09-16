rule TTP_XOR_MULT_DOSStub_6df2 {
  strings:
    $key_6df2 = { 39 9a [2] 4d 82 [2] 0a 80 [2] 4d 91 [2] 03 9d [2] 0f 97 [2] 18 9c [2] 03 d2 [2] 3e }

  condition:
    any of them
}