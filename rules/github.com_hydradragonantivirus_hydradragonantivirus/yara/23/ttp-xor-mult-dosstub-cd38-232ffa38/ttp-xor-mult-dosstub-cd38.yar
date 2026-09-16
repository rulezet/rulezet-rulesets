rule TTP_XOR_MULT_DOSStub_cd38 {
  strings:
    $key_cd38 = { 99 50 [2] ed 48 [2] aa 4a [2] ed 5b [2] a3 57 [2] af 5d [2] b8 56 [2] a3 18 [2] 9e }

  condition:
    any of them
}