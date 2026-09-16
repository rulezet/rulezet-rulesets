rule TTP_XOR_MULT_DOSStub_cd66 {
  strings:
    $key_cd66 = { 99 0e [2] ed 16 [2] aa 14 [2] ed 05 [2] a3 09 [2] af 03 [2] b8 08 [2] a3 46 [2] 9e }

  condition:
    any of them
}