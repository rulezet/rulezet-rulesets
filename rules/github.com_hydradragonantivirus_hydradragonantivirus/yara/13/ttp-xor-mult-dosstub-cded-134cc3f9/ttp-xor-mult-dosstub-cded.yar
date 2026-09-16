rule TTP_XOR_MULT_DOSStub_cded {
  strings:
    $key_cded = { 99 85 [2] ed 9d [2] aa 9f [2] ed 8e [2] a3 82 [2] af 88 [2] b8 83 [2] a3 cd [2] 9e }

  condition:
    any of them
}