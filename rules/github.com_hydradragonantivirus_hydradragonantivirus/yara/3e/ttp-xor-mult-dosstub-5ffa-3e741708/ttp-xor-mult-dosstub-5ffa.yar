rule TTP_XOR_MULT_DOSStub_5ffa {
  strings:
    $key_5ffa = { 0b 92 [2] 7f 8a [2] 38 88 [2] 7f 99 [2] 31 95 [2] 3d 9f [2] 2a 94 [2] 31 da [2] 0c }

  condition:
    any of them
}