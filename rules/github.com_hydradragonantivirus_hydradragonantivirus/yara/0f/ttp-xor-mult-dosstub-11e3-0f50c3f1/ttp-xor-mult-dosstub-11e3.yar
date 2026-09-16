rule TTP_XOR_MULT_DOSStub_11e3 {
  strings:
    $key_11e3 = { 45 8b [2] 31 93 [2] 76 91 [2] 31 80 [2] 7f 8c [2] 73 86 [2] 64 8d [2] 7f c3 [2] 42 }

  condition:
    any of them
}