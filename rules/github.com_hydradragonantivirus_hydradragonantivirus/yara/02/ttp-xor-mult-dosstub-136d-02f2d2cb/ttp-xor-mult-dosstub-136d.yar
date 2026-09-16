rule TTP_XOR_MULT_DOSStub_136d {
  strings:
    $key_136d = { 47 05 [2] 33 1d [2] 74 1f [2] 33 0e [2] 7d 02 [2] 71 08 [2] 66 03 [2] 7d 4d [2] 40 }

  condition:
    any of them
}