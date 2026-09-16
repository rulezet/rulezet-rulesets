rule TTP_XOR_MULT_DOSStub_cd29 {
  strings:
    $key_cd29 = { 99 41 [2] ed 59 [2] aa 5b [2] ed 4a [2] a3 46 [2] af 4c [2] b8 47 [2] a3 09 [2] 9e }

  condition:
    any of them
}