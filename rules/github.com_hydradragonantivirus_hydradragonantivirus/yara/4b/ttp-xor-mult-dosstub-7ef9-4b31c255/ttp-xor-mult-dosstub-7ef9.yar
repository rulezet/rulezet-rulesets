rule TTP_XOR_MULT_DOSStub_7ef9 {
  strings:
    $key_7ef9 = { 2a 91 [2] 5e 89 [2] 19 8b [2] 5e 9a [2] 10 96 [2] 1c 9c [2] 0b 97 [2] 10 d9 [2] 2d }

  condition:
    any of them
}