rule TTP_XOR_MULT_DOSStub_3f64 {
  strings:
    $key_3f64 = { 6b 0c [2] 1f 14 [2] 58 16 [2] 1f 07 [2] 51 0b [2] 5d 01 [2] 4a 0a [2] 51 44 [2] 6c }

  condition:
    any of them
}