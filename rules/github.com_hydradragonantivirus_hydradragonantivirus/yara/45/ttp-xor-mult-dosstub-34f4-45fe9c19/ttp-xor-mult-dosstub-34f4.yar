rule TTP_XOR_MULT_DOSStub_34f4 {
  strings:
    $key_34f4 = { 60 9c [2] 14 84 [2] 53 86 [2] 14 97 [2] 5a 9b [2] 56 91 [2] 41 9a [2] 5a d4 [2] 67 }

  condition:
    any of them
}