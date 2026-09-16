rule TTP_XOR_MULT_DOSStub_cd7e {
  strings:
    $key_cd7e = { 99 16 [2] ed 0e [2] aa 0c [2] ed 1d [2] a3 11 [2] af 1b [2] b8 10 [2] a3 5e [2] 9e }

  condition:
    any of them
}