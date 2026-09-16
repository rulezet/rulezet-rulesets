rule TTP_XOR_MULT_DOSStub_2f11 {
  strings:
    $key_2f11 = { 7b 79 [2] 0f 61 [2] 48 63 [2] 0f 72 [2] 41 7e [2] 4d 74 [2] 5a 7f [2] 41 31 [2] 7c }

  condition:
    any of them
}