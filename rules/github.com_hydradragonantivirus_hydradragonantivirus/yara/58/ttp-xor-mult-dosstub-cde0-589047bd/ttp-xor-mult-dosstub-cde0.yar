rule TTP_XOR_MULT_DOSStub_cde0 {
  strings:
    $key_cde0 = { 99 88 [2] ed 90 [2] aa 92 [2] ed 83 [2] a3 8f [2] af 85 [2] b8 8e [2] a3 c0 [2] 9e }

  condition:
    any of them
}