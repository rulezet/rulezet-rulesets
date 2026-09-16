rule TTP_XOR_MULT_DOSStub_cda4 {
  strings:
    $key_cda4 = { 99 cc [2] ed d4 [2] aa d6 [2] ed c7 [2] a3 cb [2] af c1 [2] b8 ca [2] a3 84 [2] 9e }

  condition:
    any of them
}