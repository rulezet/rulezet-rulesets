rule TTP_XOR_MULT_DOSStub_c537 {
  strings:
    $key_c537 = { 91 5f [2] e5 47 [2] a2 45 [2] e5 54 [2] ab 58 [2] a7 52 [2] b0 59 [2] ab 17 [2] 96 }

  condition:
    any of them
}