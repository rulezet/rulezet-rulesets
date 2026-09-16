rule TTP_XOR_MULT_DOSStub_110d {
  strings:
    $key_110d = { 45 65 [2] 31 7d [2] 76 7f [2] 31 6e [2] 7f 62 [2] 73 68 [2] 64 63 [2] 7f 2d [2] 42 }

  condition:
    any of them
}