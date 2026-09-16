rule TTP_XOR_MULT_DOSStub_d611 {
  strings:
    $key_d611 = { 82 79 [2] f6 61 [2] b1 63 [2] f6 72 [2] b8 7e [2] b4 74 [2] a3 7f [2] b8 31 [2] 85 }

  condition:
    any of them
}