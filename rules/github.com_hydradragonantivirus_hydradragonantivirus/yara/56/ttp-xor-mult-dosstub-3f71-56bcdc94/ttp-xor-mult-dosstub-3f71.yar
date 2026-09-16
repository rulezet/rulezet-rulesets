rule TTP_XOR_MULT_DOSStub_3f71 {
  strings:
    $key_3f71 = { 6b 19 [2] 1f 01 [2] 58 03 [2] 1f 12 [2] 51 1e [2] 5d 14 [2] 4a 1f [2] 51 51 [2] 6c }

  condition:
    any of them
}