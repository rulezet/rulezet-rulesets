rule TTP_XOR_MULT_DOSStub_19ec {
  strings:
    $key_19ec = { 4d 84 [2] 39 9c [2] 7e 9e [2] 39 8f [2] 77 83 [2] 7b 89 [2] 6c 82 [2] 77 cc [2] 4a }

  condition:
    any of them
}