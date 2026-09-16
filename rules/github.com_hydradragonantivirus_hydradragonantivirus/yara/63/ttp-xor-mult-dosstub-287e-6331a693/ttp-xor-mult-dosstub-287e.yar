rule TTP_XOR_MULT_DOSStub_287e {
  strings:
    $key_287e = { 7c 16 [2] 08 0e [2] 4f 0c [2] 08 1d [2] 46 11 [2] 4a 1b [2] 5d 10 [2] 46 5e [2] 7b }

  condition:
    any of them
}