rule TTP_XOR_MULT_DOSStub_692c {
  strings:
    $key_692c = { 3d 44 [2] 49 5c [2] 0e 5e [2] 49 4f [2] 07 43 [2] 0b 49 [2] 1c 42 [2] 07 0c [2] 3a }

  condition:
    any of them
}