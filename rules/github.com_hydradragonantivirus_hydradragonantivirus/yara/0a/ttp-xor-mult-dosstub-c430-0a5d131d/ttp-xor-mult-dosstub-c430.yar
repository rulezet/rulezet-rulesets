rule TTP_XOR_MULT_DOSStub_c430 {
  strings:
    $key_c430 = { 90 58 [2] e4 40 [2] a3 42 [2] e4 53 [2] aa 5f [2] a6 55 [2] b1 5e [2] aa 10 [2] 97 }

  condition:
    any of them
}