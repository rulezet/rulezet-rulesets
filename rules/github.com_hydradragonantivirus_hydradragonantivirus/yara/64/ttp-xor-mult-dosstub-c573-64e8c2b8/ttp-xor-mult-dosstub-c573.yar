rule TTP_XOR_MULT_DOSStub_c573 {
  strings:
    $key_c573 = { 91 1b [2] e5 03 [2] a2 01 [2] e5 10 [2] ab 1c [2] a7 16 [2] b0 1d [2] ab 53 [2] 96 }

  condition:
    any of them
}