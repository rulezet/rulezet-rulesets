rule TTP_XOR_MULT_DOSStub_210d {
  strings:
    $key_210d = { 75 65 [2] 01 7d [2] 46 7f [2] 01 6e [2] 4f 62 [2] 43 68 [2] 54 63 [2] 4f 2d [2] 72 }

  condition:
    any of them
}