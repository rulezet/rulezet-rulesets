rule TTP_XOR_MULT_DOSStub_65f4 {
  strings:
    $key_65f4 = { 31 9c [2] 45 84 [2] 02 86 [2] 45 97 [2] 0b 9b [2] 07 91 [2] 10 9a [2] 0b d4 [2] 36 }

  condition:
    any of them
}