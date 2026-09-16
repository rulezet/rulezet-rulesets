rule TTP_XOR_MULT_DOSStub_cdf2 {
  strings:
    $key_cdf2 = { 99 9a [2] ed 82 [2] aa 80 [2] ed 91 [2] a3 9d [2] af 97 [2] b8 9c [2] a3 d2 [2] 9e }

  condition:
    any of them
}