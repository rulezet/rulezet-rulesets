rule TTP_XOR_MULT_DOSStub_5f64 {
  strings:
    $key_5f64 = { 0b 0c [2] 7f 14 [2] 38 16 [2] 7f 07 [2] 31 0b [2] 3d 01 [2] 2a 0a [2] 31 44 [2] 0c }

  condition:
    any of them
}