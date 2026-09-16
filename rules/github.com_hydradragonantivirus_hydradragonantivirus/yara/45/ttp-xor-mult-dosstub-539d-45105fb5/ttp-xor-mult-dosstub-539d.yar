rule TTP_XOR_MULT_DOSStub_539d {
  strings:
    $key_539d = { 07 f5 [2] 73 ed [2] 34 ef [2] 73 fe [2] 3d f2 [2] 31 f8 [2] 26 f3 [2] 3d bd [2] 00 }

  condition:
    any of them
}