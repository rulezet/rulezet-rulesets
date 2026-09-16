rule TTP_XOR_MULT_DOSStub_666d {
  strings:
    $key_666d = { 32 05 [2] 46 1d [2] 01 1f [2] 46 0e [2] 08 02 [2] 04 08 [2] 13 03 [2] 08 4d [2] 35 }

  condition:
    any of them
}