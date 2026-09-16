rule TTP_XOR_MULT_DOSStub_1dfb {
  strings:
    $key_1dfb = { 49 93 [2] 3d 8b [2] 7a 89 [2] 3d 98 [2] 73 94 [2] 7f 9e [2] 68 95 [2] 73 db [2] 4e }

  condition:
    any of them
}