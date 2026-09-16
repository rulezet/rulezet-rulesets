rule TTP_XOR_MULT_DOSStub_cd43 {
  strings:
    $key_cd43 = { 99 2b [2] ed 33 [2] aa 31 [2] ed 20 [2] a3 2c [2] af 26 [2] b8 2d [2] a3 63 [2] 9e }

  condition:
    any of them
}