rule TTP_XOR_MULT_DOSStub_115d {
  strings:
    $key_115d = { 45 35 [2] 31 2d [2] 76 2f [2] 31 3e [2] 7f 32 [2] 73 38 [2] 64 33 [2] 7f 7d [2] 42 }

  condition:
    any of them
}