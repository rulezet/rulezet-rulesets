rule TTP_XOR_MULT_DOSStub_cdf5 {
  strings:
    $key_cdf5 = { 99 9d [2] ed 85 [2] aa 87 [2] ed 96 [2] a3 9a [2] af 90 [2] b8 9b [2] a3 d5 [2] 9e }

  condition:
    any of them
}