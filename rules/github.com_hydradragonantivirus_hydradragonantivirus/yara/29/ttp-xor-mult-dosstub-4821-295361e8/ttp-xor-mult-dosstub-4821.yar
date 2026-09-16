rule TTP_XOR_MULT_DOSStub_4821 {
  strings:
    $key_4821 = { 1c 49 [2] 68 51 [2] 2f 53 [2] 68 42 [2] 26 4e [2] 2a 44 [2] 3d 4f [2] 26 01 [2] 1b }

  condition:
    any of them
}