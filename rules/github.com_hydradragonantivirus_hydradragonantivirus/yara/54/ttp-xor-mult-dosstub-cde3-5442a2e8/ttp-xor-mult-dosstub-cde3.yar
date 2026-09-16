rule TTP_XOR_MULT_DOSStub_cde3 {
  strings:
    $key_cde3 = { 99 8b [2] ed 93 [2] aa 91 [2] ed 80 [2] a3 8c [2] af 86 [2] b8 8d [2] a3 c3 [2] 9e }

  condition:
    any of them
}