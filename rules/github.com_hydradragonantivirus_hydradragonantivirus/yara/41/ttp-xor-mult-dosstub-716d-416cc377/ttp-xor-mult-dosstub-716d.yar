rule TTP_XOR_MULT_DOSStub_716d {
  strings:
    $key_716d = { 25 05 [2] 51 1d [2] 16 1f [2] 51 0e [2] 1f 02 [2] 13 08 [2] 04 03 [2] 1f 4d [2] 22 }

  condition:
    any of them
}