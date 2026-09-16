rule TTP_XOR_MULT_DOSStub_3afd {
  strings:
    $key_3afd = { 6e 95 [2] 1a 8d [2] 5d 8f [2] 1a 9e [2] 54 92 [2] 58 98 [2] 4f 93 [2] 54 dd [2] 69 }

  condition:
    any of them
}