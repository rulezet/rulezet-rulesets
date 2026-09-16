rule TTP_XOR_MULT_DOSStub_287d {
  strings:
    $key_287d = { 7c 15 [2] 08 0d [2] 4f 0f [2] 08 1e [2] 46 12 [2] 4a 18 [2] 5d 13 [2] 46 5d [2] 7b }

  condition:
    any of them
}