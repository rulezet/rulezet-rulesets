rule TTP_XOR_MULT_DOSStub_692b {
  strings:
    $key_692b = { 3d 43 [2] 49 5b [2] 0e 59 [2] 49 48 [2] 07 44 [2] 0b 4e [2] 1c 45 [2] 07 0b [2] 3a }

  condition:
    any of them
}