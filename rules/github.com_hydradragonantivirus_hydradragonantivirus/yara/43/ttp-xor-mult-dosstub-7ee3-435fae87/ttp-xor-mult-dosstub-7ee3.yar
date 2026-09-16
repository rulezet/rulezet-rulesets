rule TTP_XOR_MULT_DOSStub_7ee3 {
  strings:
    $key_7ee3 = { 2a 8b [2] 5e 93 [2] 19 91 [2] 5e 80 [2] 10 8c [2] 1c 86 [2] 0b 8d [2] 10 c3 [2] 2d }

  condition:
    any of them
}