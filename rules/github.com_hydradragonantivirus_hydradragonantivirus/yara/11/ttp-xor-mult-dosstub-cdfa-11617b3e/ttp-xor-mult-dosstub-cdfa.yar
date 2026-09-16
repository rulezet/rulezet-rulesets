rule TTP_XOR_MULT_DOSStub_cdfa {
  strings:
    $key_cdfa = { 99 92 [2] ed 8a [2] aa 88 [2] ed 99 [2] a3 95 [2] af 9f [2] b8 94 [2] a3 da [2] 9e }

  condition:
    any of them
}