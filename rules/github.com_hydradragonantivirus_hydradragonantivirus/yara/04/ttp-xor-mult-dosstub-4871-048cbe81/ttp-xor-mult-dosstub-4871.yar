rule TTP_XOR_MULT_DOSStub_4871 {
  strings:
    $key_4871 = { 1c 19 [2] 68 01 [2] 2f 03 [2] 68 12 [2] 26 1e [2] 2a 14 [2] 3d 1f [2] 26 51 [2] 1b }

  condition:
    any of them
}