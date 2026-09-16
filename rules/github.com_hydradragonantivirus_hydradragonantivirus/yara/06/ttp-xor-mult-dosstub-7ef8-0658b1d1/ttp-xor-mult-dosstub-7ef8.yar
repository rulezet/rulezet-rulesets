rule TTP_XOR_MULT_DOSStub_7ef8 {
  strings:
    $key_7ef8 = { 2a 90 [2] 5e 88 [2] 19 8a [2] 5e 9b [2] 10 97 [2] 1c 9d [2] 0b 96 [2] 10 d8 [2] 2d }

  condition:
    any of them
}