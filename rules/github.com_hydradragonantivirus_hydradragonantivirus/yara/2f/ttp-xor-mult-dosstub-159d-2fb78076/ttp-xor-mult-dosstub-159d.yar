rule TTP_XOR_MULT_DOSStub_159d {
  strings:
    $key_159d = { 41 f5 [2] 35 ed [2] 72 ef [2] 35 fe [2] 7b f2 [2] 77 f8 [2] 60 f3 [2] 7b bd [2] 46 }

  condition:
    any of them
}