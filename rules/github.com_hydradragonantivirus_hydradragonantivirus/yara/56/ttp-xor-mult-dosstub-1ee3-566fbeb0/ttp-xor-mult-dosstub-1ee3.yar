rule TTP_XOR_MULT_DOSStub_1ee3 {
  strings:
    $key_1ee3 = { 4a 8b [2] 3e 93 [2] 79 91 [2] 3e 80 [2] 70 8c [2] 7c 86 [2] 6b 8d [2] 70 c3 [2] 4d }

  condition:
    any of them
}