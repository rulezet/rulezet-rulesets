rule TTP_XOR_MULT_DOSStub_0271 {
  strings:
    $key_0271 = { 56 19 [2] 22 01 [2] 65 03 [2] 22 12 [2] 6c 1e [2] 60 14 [2] 77 1f [2] 6c 51 [2] 51 }

  condition:
    any of them
}