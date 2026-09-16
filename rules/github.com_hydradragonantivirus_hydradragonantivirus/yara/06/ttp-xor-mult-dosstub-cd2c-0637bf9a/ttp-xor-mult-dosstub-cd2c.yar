rule TTP_XOR_MULT_DOSStub_cd2c {
  strings:
    $key_cd2c = { 99 44 [2] ed 5c [2] aa 5e [2] ed 4f [2] a3 43 [2] af 49 [2] b8 42 [2] a3 0c [2] 9e }

  condition:
    any of them
}