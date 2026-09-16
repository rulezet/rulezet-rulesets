rule TTP_XOR_MULT_DOSStub_1f64 {
  strings:
    $key_1f64 = { 4b 0c [2] 3f 14 [2] 78 16 [2] 3f 07 [2] 71 0b [2] 7d 01 [2] 6a 0a [2] 71 44 [2] 4c }

  condition:
    any of them
}