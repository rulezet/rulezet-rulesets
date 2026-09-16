rule TTP_XOR_MULT_DOSStub_6e01 {
  strings:
    $key_6e01 = { 3a 69 [2] 4e 71 [2] 09 73 [2] 4e 62 [2] 00 6e [2] 0c 64 [2] 1b 6f [2] 00 21 [2] 3d }

  condition:
    any of them
}