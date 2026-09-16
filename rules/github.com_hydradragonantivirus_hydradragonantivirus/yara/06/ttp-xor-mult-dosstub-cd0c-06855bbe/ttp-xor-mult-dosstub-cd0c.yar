rule TTP_XOR_MULT_DOSStub_cd0c {
  strings:
    $key_cd0c = { 99 64 [2] ed 7c [2] aa 7e [2] ed 6f [2] a3 63 [2] af 69 [2] b8 62 [2] a3 2c [2] 9e }

  condition:
    any of them
}