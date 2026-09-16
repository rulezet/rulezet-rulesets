rule TTP_XOR_MULT_DOSStub_7e38 {
  strings:
    $key_7e38 = { 2a 50 [2] 5e 48 [2] 19 4a [2] 5e 5b [2] 10 57 [2] 1c 5d [2] 0b 56 [2] 10 18 [2] 2d }

  condition:
    any of them
}