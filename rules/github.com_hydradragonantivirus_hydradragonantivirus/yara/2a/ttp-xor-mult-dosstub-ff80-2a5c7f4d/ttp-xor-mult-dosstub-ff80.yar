rule TTP_XOR_MULT_DOSStub_ff80 {
  strings:
    $key_ff80 = { ab e8 [2] df f0 [2] 98 f2 [2] df e3 [2] 91 ef [2] 9d e5 [2] 8a ee [2] 91 a0 [2] ac }

  condition:
    any of them
}