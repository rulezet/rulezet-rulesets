rule TTP_XOR_MULT_DOSStub_cd99 {
  strings:
    $key_cd99 = { 99 f1 [2] ed e9 [2] aa eb [2] ed fa [2] a3 f6 [2] af fc [2] b8 f7 [2] a3 b9 [2] 9e }

  condition:
    any of them
}