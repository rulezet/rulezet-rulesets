rule TTP_XOR_MULT_DOSStub_cd1d {
  strings:
    $key_cd1d = { 99 75 [2] ed 6d [2] aa 6f [2] ed 7e [2] a3 72 [2] af 78 [2] b8 73 [2] a3 3d [2] 9e }

  condition:
    any of them
}