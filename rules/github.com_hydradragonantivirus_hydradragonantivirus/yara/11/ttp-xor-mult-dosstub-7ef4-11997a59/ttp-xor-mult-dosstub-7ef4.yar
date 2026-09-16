rule TTP_XOR_MULT_DOSStub_7ef4 {
  strings:
    $key_7ef4 = { 2a 9c [2] 5e 84 [2] 19 86 [2] 5e 97 [2] 10 9b [2] 1c 91 [2] 0b 9a [2] 10 d4 [2] 2d }

  condition:
    any of them
}