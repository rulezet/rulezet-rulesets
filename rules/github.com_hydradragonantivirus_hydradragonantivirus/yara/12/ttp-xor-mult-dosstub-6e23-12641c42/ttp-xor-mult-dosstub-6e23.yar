rule TTP_XOR_MULT_DOSStub_6e23 {
  strings:
    $key_6e23 = { 3a 4b [2] 4e 53 [2] 09 51 [2] 4e 40 [2] 00 4c [2] 0c 46 [2] 1b 4d [2] 00 03 [2] 3d }

  condition:
    any of them
}