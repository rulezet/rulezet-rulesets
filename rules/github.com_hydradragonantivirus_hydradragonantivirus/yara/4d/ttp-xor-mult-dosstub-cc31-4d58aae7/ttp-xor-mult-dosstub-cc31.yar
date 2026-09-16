rule TTP_XOR_MULT_DOSStub_cc31 {
  strings:
    $key_cc31 = { 98 59 [2] ec 41 [2] ab 43 [2] ec 52 [2] a2 5e [2] ae 54 [2] b9 5f [2] a2 11 [2] 9f }

  condition:
    any of them
}