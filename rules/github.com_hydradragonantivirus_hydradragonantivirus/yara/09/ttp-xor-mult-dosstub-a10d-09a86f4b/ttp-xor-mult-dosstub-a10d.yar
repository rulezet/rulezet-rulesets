rule TTP_XOR_MULT_DOSStub_a10d {
  strings:
    $key_a10d = { f5 65 [2] 81 7d [2] c6 7f [2] 81 6e [2] cf 62 [2] c3 68 [2] d4 63 [2] cf 2d [2] f2 }

  condition:
    any of them
}