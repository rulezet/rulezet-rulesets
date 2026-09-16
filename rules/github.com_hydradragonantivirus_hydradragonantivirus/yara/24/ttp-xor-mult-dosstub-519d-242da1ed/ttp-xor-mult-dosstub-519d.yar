rule TTP_XOR_MULT_DOSStub_519d {
  strings:
    $key_519d = { 05 f5 [2] 71 ed [2] 36 ef [2] 71 fe [2] 3f f2 [2] 33 f8 [2] 24 f3 [2] 3f bd [2] 02 }

  condition:
    any of them
}