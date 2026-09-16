rule TTP_XOR_MULT_DOSStub_d79d {
  strings:
    $key_d79d = { 83 f5 [2] f7 ed [2] b0 ef [2] f7 fe [2] b9 f2 [2] b5 f8 [2] a2 f3 [2] b9 bd [2] 84 }

  condition:
    any of them
}