rule TTP_XOR_MULT_DOSStub_2876 {
  strings:
    $key_2876 = { 7c 1e [2] 08 06 [2] 4f 04 [2] 08 15 [2] 46 19 [2] 4a 13 [2] 5d 18 [2] 46 56 [2] 7b }

  condition:
    any of them
}