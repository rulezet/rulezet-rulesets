rule TTP_XOR_MULT_DOSStub_2f71 {
  strings:
    $key_2f71 = { 7b 19 [2] 0f 01 [2] 48 03 [2] 0f 12 [2] 41 1e [2] 4d 14 [2] 5a 1f [2] 41 51 [2] 7c }

  condition:
    any of them
}