rule TTP_XOR_MULT_DOSStub_7ef2 {
  strings:
    $key_7ef2 = { 2a 9a [2] 5e 82 [2] 19 80 [2] 5e 91 [2] 10 9d [2] 1c 97 [2] 0b 9c [2] 10 d2 [2] 2d }

  condition:
    any of them
}