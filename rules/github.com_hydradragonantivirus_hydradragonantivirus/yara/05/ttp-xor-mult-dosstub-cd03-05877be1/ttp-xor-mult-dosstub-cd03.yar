rule TTP_XOR_MULT_DOSStub_cd03 {
  strings:
    $key_cd03 = { 99 6b [2] ed 73 [2] aa 71 [2] ed 60 [2] a3 6c [2] af 66 [2] b8 6d [2] a3 23 [2] 9e }

  condition:
    any of them
}