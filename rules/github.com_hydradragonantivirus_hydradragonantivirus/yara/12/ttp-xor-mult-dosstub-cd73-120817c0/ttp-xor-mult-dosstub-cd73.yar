rule TTP_XOR_MULT_DOSStub_cd73 {
  strings:
    $key_cd73 = { 99 1b [2] ed 03 [2] aa 01 [2] ed 10 [2] a3 1c [2] af 16 [2] b8 1d [2] a3 53 [2] 9e }

  condition:
    any of them
}