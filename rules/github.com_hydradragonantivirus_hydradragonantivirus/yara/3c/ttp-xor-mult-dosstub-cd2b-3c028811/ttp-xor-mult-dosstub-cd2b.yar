rule TTP_XOR_MULT_DOSStub_cd2b {
  strings:
    $key_cd2b = { 99 43 [2] ed 5b [2] aa 59 [2] ed 48 [2] a3 44 [2] af 4e [2] b8 45 [2] a3 0b [2] 9e }

  condition:
    any of them
}