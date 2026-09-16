rule TTP_XOR_MULT_DOSStub_2ef9 {
  strings:
    $key_2ef9 = { 7a 91 [2] 0e 89 [2] 49 8b [2] 0e 9a [2] 40 96 [2] 4c 9c [2] 5b 97 [2] 40 d9 [2] 7d }

  condition:
    any of them
}