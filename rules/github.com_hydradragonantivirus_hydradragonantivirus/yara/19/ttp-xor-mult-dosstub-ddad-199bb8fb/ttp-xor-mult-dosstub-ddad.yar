rule TTP_XOR_MULT_DOSStub_ddad {
  strings:
    $key_ddad = { 89 c5 [2] fd dd [2] ba df [2] fd ce [2] b3 c2 [2] bf c8 [2] a8 c3 [2] b3 8d [2] 8e }

  condition:
    any of them
}