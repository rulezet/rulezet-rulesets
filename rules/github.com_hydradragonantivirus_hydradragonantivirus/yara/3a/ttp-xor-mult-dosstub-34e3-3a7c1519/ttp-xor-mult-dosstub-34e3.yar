rule TTP_XOR_MULT_DOSStub_34e3 {
  strings:
    $key_34e3 = { 60 8b [2] 14 93 [2] 53 91 [2] 14 80 [2] 5a 8c [2] 56 86 [2] 41 8d [2] 5a c3 [2] 67 }

  condition:
    any of them
}