rule TTP_XOR_MULT_DOSStub_4be3 {
  strings:
    $key_4be3 = { 1f 8b [2] 6b 93 [2] 2c 91 [2] 6b 80 [2] 25 8c [2] 29 86 [2] 3e 8d [2] 25 c3 [2] 18 }

  condition:
    any of them
}