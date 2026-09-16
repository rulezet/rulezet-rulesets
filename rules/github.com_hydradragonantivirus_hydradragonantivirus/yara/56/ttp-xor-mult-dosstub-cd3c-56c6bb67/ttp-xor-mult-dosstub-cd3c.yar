rule TTP_XOR_MULT_DOSStub_cd3c {
  strings:
    $key_cd3c = { 99 54 [2] ed 4c [2] aa 4e [2] ed 5f [2] a3 53 [2] af 59 [2] b8 52 [2] a3 1c [2] 9e }

  condition:
    any of them
}