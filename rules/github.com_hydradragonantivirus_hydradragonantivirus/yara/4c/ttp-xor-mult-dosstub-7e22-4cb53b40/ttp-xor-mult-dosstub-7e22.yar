rule TTP_XOR_MULT_DOSStub_7e22 {
  strings:
    $key_7e22 = { 2a 4a [2] 5e 52 [2] 19 50 [2] 5e 41 [2] 10 4d [2] 1c 47 [2] 0b 4c [2] 10 02 [2] 2d }

  condition:
    any of them
}