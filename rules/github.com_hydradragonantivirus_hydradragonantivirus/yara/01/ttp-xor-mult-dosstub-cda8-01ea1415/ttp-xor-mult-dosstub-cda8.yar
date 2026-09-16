rule TTP_XOR_MULT_DOSStub_cda8 {
  strings:
    $key_cda8 = { 99 c0 [2] ed d8 [2] aa da [2] ed cb [2] a3 c7 [2] af cd [2] b8 c6 [2] a3 88 [2] 9e }

  condition:
    any of them
}