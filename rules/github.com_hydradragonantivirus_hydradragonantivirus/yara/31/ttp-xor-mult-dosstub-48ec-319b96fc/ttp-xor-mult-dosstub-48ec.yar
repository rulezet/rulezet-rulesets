rule TTP_XOR_MULT_DOSStub_48ec {
  strings:
    $key_48ec = { 1c 84 [2] 68 9c [2] 2f 9e [2] 68 8f [2] 26 83 [2] 2a 89 [2] 3d 82 [2] 26 cc [2] 1b }

  condition:
    any of them
}