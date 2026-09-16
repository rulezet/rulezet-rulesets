rule TTP_XOR_MULT_DOSStub_0f71 {
  strings:
    $key_0f71 = { 5b 19 [2] 2f 01 [2] 68 03 [2] 2f 12 [2] 61 1e [2] 6d 14 [2] 7a 1f [2] 61 51 [2] 5c }

  condition:
    any of them
}