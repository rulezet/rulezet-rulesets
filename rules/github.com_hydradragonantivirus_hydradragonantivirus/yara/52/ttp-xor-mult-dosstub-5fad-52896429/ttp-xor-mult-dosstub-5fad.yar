rule TTP_XOR_MULT_DOSStub_5fad {
  strings:
    $key_5fad = { 0b c5 [2] 7f dd [2] 38 df [2] 7f ce [2] 31 c2 [2] 3d c8 [2] 2a c3 [2] 31 8d [2] 0c }

  condition:
    any of them
}