rule TTP_XOR_MULT_DOSStub_6933 {
  strings:
    $key_6933 = { 3d 5b [2] 49 43 [2] 0e 41 [2] 49 50 [2] 07 5c [2] 0b 56 [2] 1c 5d [2] 07 13 [2] 3a }

  condition:
    any of them
}