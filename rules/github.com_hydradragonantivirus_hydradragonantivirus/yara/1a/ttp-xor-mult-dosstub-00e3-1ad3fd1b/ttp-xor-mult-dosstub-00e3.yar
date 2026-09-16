rule TTP_XOR_MULT_DOSStub_00e3 {
  strings:
    $key_00e3 = { 54 8b [2] 20 93 [2] 67 91 [2] 20 80 [2] 6e 8c [2] 62 86 [2] 75 8d [2] 6e c3 [2] 53 }

  condition:
    any of them
}