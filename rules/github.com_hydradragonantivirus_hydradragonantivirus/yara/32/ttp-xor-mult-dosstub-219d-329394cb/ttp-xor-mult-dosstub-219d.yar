rule TTP_XOR_MULT_DOSStub_219d {
  strings:
    $key_219d = { 75 f5 [2] 01 ed [2] 46 ef [2] 01 fe [2] 4f f2 [2] 43 f8 [2] 54 f3 [2] 4f bd [2] 72 }

  condition:
    any of them
}