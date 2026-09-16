rule TTP_XOR_MULT_DOSStub_c503 {
  strings:
    $key_c503 = { 91 6b [2] e5 73 [2] a2 71 [2] e5 60 [2] ab 6c [2] a7 66 [2] b0 6d [2] ab 23 [2] 96 }

  condition:
    any of them
}