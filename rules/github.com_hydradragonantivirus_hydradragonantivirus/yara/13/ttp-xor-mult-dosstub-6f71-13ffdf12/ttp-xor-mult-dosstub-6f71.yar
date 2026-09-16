rule TTP_XOR_MULT_DOSStub_6f71 {
  strings:
    $key_6f71 = { 3b 19 [2] 4f 01 [2] 08 03 [2] 4f 12 [2] 01 1e [2] 0d 14 [2] 1a 1f [2] 01 51 [2] 3c }

  condition:
    any of them
}