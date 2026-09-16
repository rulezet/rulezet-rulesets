rule TTP_XOR_MULT_DOSStub_d7e3 {
  strings:
    $key_d7e3 = { 83 8b [2] f7 93 [2] b0 91 [2] f7 80 [2] b9 8c [2] b5 86 [2] a2 8d [2] b9 c3 [2] 84 }

  condition:
    any of them
}