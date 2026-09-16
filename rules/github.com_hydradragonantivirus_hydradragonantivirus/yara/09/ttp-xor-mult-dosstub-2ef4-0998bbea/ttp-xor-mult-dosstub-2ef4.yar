rule TTP_XOR_MULT_DOSStub_2ef4 {
  strings:
    $key_2ef4 = { 7a 9c [2] 0e 84 [2] 49 86 [2] 0e 97 [2] 40 9b [2] 4c 91 [2] 5b 9a [2] 40 d4 [2] 7d }

  condition:
    any of them
}