rule TTP_XOR_MULT_DOSStub_cd1c {
  strings:
    $key_cd1c = { 99 74 [2] ed 6c [2] aa 6e [2] ed 7f [2] a3 73 [2] af 79 [2] b8 72 [2] a3 3c [2] 9e }

  condition:
    any of them
}