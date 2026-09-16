rule TTP_XOR_MULT_DOSStub_111d {
  strings:
    $key_111d = { 45 75 [2] 31 6d [2] 76 6f [2] 31 7e [2] 7f 72 [2] 73 78 [2] 64 73 [2] 7f 3d [2] 42 }

  condition:
    any of them
}