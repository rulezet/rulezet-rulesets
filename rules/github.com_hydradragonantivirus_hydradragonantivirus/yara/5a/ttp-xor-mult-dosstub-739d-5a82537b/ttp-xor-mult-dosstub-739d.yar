rule TTP_XOR_MULT_DOSStub_739d {
  strings:
    $key_739d = { 27 f5 [2] 53 ed [2] 14 ef [2] 53 fe [2] 1d f2 [2] 11 f8 [2] 06 f3 [2] 1d bd [2] 20 }

  condition:
    any of them
}