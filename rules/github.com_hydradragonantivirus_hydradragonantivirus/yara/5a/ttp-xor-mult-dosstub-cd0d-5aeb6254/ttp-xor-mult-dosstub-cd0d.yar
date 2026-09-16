rule TTP_XOR_MULT_DOSStub_cd0d {
  strings:
    $key_cd0d = { 99 65 [2] ed 7d [2] aa 7f [2] ed 6e [2] a3 62 [2] af 68 [2] b8 63 [2] a3 2d [2] 9e }

  condition:
    any of them
}