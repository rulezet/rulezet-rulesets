rule TTP_XOR_MULT_DOSStub_6961 {
  strings:
    $key_6961 = { 3d 09 [2] 49 11 [2] 0e 13 [2] 49 02 [2] 07 0e [2] 0b 04 [2] 1c 0f [2] 07 41 [2] 3a }

  condition:
    any of them
}