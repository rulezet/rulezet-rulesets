rule TTP_XOR_MULT_DOSStub_66ec {
  strings:
    $key_66ec = { 32 84 [2] 46 9c [2] 01 9e [2] 46 8f [2] 08 83 [2] 04 89 [2] 13 82 [2] 08 cc [2] 35 }

  condition:
    any of them
}