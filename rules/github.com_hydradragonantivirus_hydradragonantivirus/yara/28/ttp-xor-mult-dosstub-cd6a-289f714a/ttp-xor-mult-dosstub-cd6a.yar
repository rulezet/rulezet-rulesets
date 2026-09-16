rule TTP_XOR_MULT_DOSStub_cd6a {
  strings:
    $key_cd6a = { 99 02 [2] ed 1a [2] aa 18 [2] ed 09 [2] a3 05 [2] af 0f [2] b8 04 [2] a3 4a [2] 9e }

  condition:
    any of them
}