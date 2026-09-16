rule TTP_XOR_MULT_DOSStub_1fad {
  strings:
    $key_1fad = { 4b c5 [2] 3f dd [2] 78 df [2] 3f ce [2] 71 c2 [2] 7d c8 [2] 6a c3 [2] 71 8d [2] 4c }

  condition:
    any of them
}