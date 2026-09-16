rule TTP_XOR_MULT_DOSStub_cd61 {
  strings:
    $key_cd61 = { 99 09 [2] ed 11 [2] aa 13 [2] ed 02 [2] a3 0e [2] af 04 [2] b8 0f [2] a3 41 [2] 9e }

  condition:
    any of them
}