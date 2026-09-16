rule TTP_XOR_MULT_DOSStub_e59d {
  strings:
    $key_e59d = { b1 f5 [2] c5 ed [2] 82 ef [2] c5 fe [2] 8b f2 [2] 87 f8 [2] 90 f3 [2] 8b bd [2] b6 }

  condition:
    any of them
}