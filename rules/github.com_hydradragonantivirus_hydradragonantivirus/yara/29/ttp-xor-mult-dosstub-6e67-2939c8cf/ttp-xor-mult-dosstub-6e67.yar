rule TTP_XOR_MULT_DOSStub_6e67 {
  strings:
    $key_6e67 = { 3a 0f [2] 4e 17 [2] 09 15 [2] 4e 04 [2] 00 08 [2] 0c 02 [2] 1b 09 [2] 00 47 [2] 3d }

  condition:
    any of them
}