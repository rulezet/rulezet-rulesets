rule TTP_XOR_MULT_DOSStub_28ec {
  strings:
    $key_28ec = { 7c 84 [2] 08 9c [2] 4f 9e [2] 08 8f [2] 46 83 [2] 4a 89 [2] 5d 82 [2] 46 cc [2] 7b }

  condition:
    any of them
}