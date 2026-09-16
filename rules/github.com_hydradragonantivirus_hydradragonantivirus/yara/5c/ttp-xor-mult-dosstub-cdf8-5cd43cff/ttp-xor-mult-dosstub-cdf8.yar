rule TTP_XOR_MULT_DOSStub_cdf8 {
  strings:
    $key_cdf8 = { 99 90 [2] ed 88 [2] aa 8a [2] ed 9b [2] a3 97 [2] af 9d [2] b8 96 [2] a3 d8 [2] 9e }

  condition:
    any of them
}