rule TTP_XOR_MULT_DOSStub_68ec {
  strings:
    $key_68ec = { 3c 84 [2] 48 9c [2] 0f 9e [2] 48 8f [2] 06 83 [2] 0a 89 [2] 1d 82 [2] 06 cc [2] 3b }

  condition:
    any of them
}