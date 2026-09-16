rule TTP_XOR_MULT_DOSStub_3aed {
  strings:
    $key_3aed = { 6e 85 [2] 1a 9d [2] 5d 9f [2] 1a 8e [2] 54 82 [2] 58 88 [2] 4f 83 [2] 54 cd [2] 69 }

  condition:
    any of them
}