rule TTP_XOR_MULT_DOSStub_3f11 {
  strings:
    $key_3f11 = { 6b 79 [2] 1f 61 [2] 58 63 [2] 1f 72 [2] 51 7e [2] 5d 74 [2] 4a 7f [2] 51 31 [2] 6c }

  condition:
    any of them
}