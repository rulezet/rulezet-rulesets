rule TTP_XOR_MULT_DOSStub_4f64 {
  strings:
    $key_4f64 = { 1b 0c [2] 6f 14 [2] 28 16 [2] 6f 07 [2] 21 0b [2] 2d 01 [2] 3a 0a [2] 21 44 [2] 1c }

  condition:
    any of them
}