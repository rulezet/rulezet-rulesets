rule TTP_XOR_MULT_DOSStub_020d {
  strings:
    $key_020d = { 56 65 [2] 22 7d [2] 65 7f [2] 22 6e [2] 6c 62 [2] 60 68 [2] 77 63 [2] 6c 2d [2] 51 }

  condition:
    any of them
}