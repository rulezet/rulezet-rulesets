rule TTP_XOR_MULT_DOSStub_02e3 {
  strings:
    $key_02e3 = { 56 8b [2] 22 93 [2] 65 91 [2] 22 80 [2] 6c 8c [2] 60 86 [2] 77 8d [2] 6c c3 [2] 51 }

  condition:
    any of them
}