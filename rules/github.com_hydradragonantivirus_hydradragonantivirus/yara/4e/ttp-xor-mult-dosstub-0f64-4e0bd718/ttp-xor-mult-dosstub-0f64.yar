rule TTP_XOR_MULT_DOSStub_0f64 {
  strings:
    $key_0f64 = { 5b 0c [2] 2f 14 [2] 68 16 [2] 2f 07 [2] 61 0b [2] 6d 01 [2] 7a 0a [2] 61 44 [2] 5c }

  condition:
    any of them
}