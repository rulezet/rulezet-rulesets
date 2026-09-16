rule TTP_XOR_MULT_DOSStub_2831 {
  strings:
    $key_2831 = { 7c 59 [2] 08 41 [2] 4f 43 [2] 08 52 [2] 46 5e [2] 4a 54 [2] 5d 5f [2] 46 11 [2] 7b }

  condition:
    any of them
}