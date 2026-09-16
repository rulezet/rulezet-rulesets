rule TTP_XOR_MULT_DOSStub_cda3 {
  strings:
    $key_cda3 = { 99 cb [2] ed d3 [2] aa d1 [2] ed c0 [2] a3 cc [2] af c6 [2] b8 cd [2] a3 83 [2] 9e }

  condition:
    any of them
}