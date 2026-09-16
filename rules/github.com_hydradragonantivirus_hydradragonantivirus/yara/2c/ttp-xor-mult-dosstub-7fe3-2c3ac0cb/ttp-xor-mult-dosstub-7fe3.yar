rule TTP_XOR_MULT_DOSStub_7fe3 {
  strings:
    $key_7fe3 = { 2b 8b [2] 5f 93 [2] 18 91 [2] 5f 80 [2] 11 8c [2] 1d 86 [2] 0a 8d [2] 11 c3 [2] 2c }

  condition:
    any of them
}