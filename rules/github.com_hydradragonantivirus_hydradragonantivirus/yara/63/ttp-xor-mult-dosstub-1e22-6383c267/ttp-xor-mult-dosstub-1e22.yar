rule TTP_XOR_MULT_DOSStub_1e22 {
  strings:
    $key_1e22 = { 4a 4a [2] 3e 52 [2] 79 50 [2] 3e 41 [2] 70 4d [2] 7c 47 [2] 6b 4c [2] 70 02 [2] 4d }

  condition:
    any of them
}