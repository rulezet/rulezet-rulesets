rule TTP_XOR_MULT_DOSStub_e561 {
  strings:
    $key_e561 = { b1 09 [2] c5 11 [2] 82 13 [2] c5 02 [2] 8b 0e [2] 87 04 [2] 90 0f [2] 8b 41 [2] b6 }

  condition:
    any of them
}