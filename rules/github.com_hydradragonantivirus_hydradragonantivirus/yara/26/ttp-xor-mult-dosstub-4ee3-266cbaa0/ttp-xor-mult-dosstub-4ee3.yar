rule TTP_XOR_MULT_DOSStub_4ee3 {
  strings:
    $key_4ee3 = { 1a 8b [2] 6e 93 [2] 29 91 [2] 6e 80 [2] 20 8c [2] 2c 86 [2] 3b 8d [2] 20 c3 [2] 1d }

  condition:
    any of them
}