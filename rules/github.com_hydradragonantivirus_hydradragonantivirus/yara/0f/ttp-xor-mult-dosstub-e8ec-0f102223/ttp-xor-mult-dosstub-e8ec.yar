rule TTP_XOR_MULT_DOSStub_e8ec {
  strings:
    $key_e8ec = { bc 84 [2] c8 9c [2] 8f 9e [2] c8 8f [2] 86 83 [2] 8a 89 [2] 9d 82 [2] 86 cc [2] bb }

  condition:
    any of them
}