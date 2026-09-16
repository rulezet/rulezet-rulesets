rule TTP_XOR_MULT_DOSStub_486d {
  strings:
    $key_486d = { 1c 05 [2] 68 1d [2] 2f 1f [2] 68 0e [2] 26 02 [2] 2a 08 [2] 3d 03 [2] 26 4d [2] 1b }

  condition:
    any of them
}