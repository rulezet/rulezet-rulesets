rule TTP_XOR_MULT_DOSStub_cd3e {
  strings:
    $key_cd3e = { 99 56 [2] ed 4e [2] aa 4c [2] ed 5d [2] a3 51 [2] af 5b [2] b8 50 [2] a3 1e [2] 9e }

  condition:
    any of them
}