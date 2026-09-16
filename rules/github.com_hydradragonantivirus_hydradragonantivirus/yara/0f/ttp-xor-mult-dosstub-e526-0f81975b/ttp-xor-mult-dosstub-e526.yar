rule TTP_XOR_MULT_DOSStub_e526 {
  strings:
    $key_e526 = { b1 4e [2] c5 56 [2] 82 54 [2] c5 45 [2] 8b 49 [2] 87 43 [2] 90 48 [2] 8b 06 [2] b6 }

  condition:
    any of them
}