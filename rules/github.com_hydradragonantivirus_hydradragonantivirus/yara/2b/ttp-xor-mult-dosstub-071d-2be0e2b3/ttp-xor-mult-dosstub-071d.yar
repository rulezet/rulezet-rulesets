rule TTP_XOR_MULT_DOSStub_071d {
  strings:
    $key_071d = { 53 75 [2] 27 6d [2] 60 6f [2] 27 7e [2] 69 72 [2] 65 78 [2] 72 73 [2] 69 3d [2] 54 }

  condition:
    any of them
}