rule TTP_XOR_MULT_DOSStub_cd5c {
  strings:
    $key_cd5c = { 99 34 [2] ed 2c [2] aa 2e [2] ed 3f [2] a3 33 [2] af 39 [2] b8 32 [2] a3 7c [2] 9e }

  condition:
    any of them
}