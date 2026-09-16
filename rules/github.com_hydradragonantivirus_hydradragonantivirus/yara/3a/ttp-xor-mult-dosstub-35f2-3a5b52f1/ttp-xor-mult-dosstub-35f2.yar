rule TTP_XOR_MULT_DOSStub_35f2 {
  strings:
    $key_35f2 = { 61 9a [2] 15 82 [2] 52 80 [2] 15 91 [2] 5b 9d [2] 57 97 [2] 40 9c [2] 5b d2 [2] 66 }

  condition:
    any of them
}