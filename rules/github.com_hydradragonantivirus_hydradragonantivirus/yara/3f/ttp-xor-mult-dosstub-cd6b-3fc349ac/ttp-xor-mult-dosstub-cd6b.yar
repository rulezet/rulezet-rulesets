rule TTP_XOR_MULT_DOSStub_cd6b {
  strings:
    $key_cd6b = { 99 03 [2] ed 1b [2] aa 19 [2] ed 08 [2] a3 04 [2] af 0e [2] b8 05 [2] a3 4b [2] 9e }

  condition:
    any of them
}