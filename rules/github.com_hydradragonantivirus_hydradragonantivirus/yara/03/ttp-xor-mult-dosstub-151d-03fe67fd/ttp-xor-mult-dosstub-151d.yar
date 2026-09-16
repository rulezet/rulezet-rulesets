rule TTP_XOR_MULT_DOSStub_151d {
  strings:
    $key_151d = { 41 75 [2] 35 6d [2] 72 6f [2] 35 7e [2] 7b 72 [2] 77 78 [2] 60 73 [2] 7b 3d [2] 46 }

  condition:
    any of them
}