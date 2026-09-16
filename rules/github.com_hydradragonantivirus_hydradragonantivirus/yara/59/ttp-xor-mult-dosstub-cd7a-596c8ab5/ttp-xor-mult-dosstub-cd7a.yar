rule TTP_XOR_MULT_DOSStub_cd7a {
  strings:
    $key_cd7a = { 99 12 [2] ed 0a [2] aa 08 [2] ed 19 [2] a3 15 [2] af 1f [2] b8 14 [2] a3 5a [2] 9e }

  condition:
    any of them
}