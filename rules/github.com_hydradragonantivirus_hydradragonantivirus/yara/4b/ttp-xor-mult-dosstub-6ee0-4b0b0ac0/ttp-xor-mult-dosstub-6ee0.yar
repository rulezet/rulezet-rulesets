rule TTP_XOR_MULT_DOSStub_6ee0 {
  strings:
    $key_6ee0 = { 3a 88 [2] 4e 90 [2] 09 92 [2] 4e 83 [2] 00 8f [2] 0c 85 [2] 1b 8e [2] 00 c0 [2] 3d }

  condition:
    any of them
}