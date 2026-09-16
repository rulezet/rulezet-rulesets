rule TTP_XOR_MULT_DOSStub_286d {
  strings:
    $key_286d = { 7c 05 [2] 08 1d [2] 4f 1f [2] 08 0e [2] 46 02 [2] 4a 08 [2] 5d 03 [2] 46 4d [2] 7b }

  condition:
    any of them
}