rule TTP_XOR_MULT_DOSStub_e511 {
  strings:
    $key_e511 = { b1 79 [2] c5 61 [2] 82 63 [2] c5 72 [2] 8b 7e [2] 87 74 [2] 90 7f [2] 8b 31 [2] b6 }

  condition:
    any of them
}