rule TTP_XOR_MULT_DOSStub_fa07 {
  strings:
    $key_fa07 = { ae 6f [2] da 77 [2] 9d 75 [2] da 64 [2] 94 68 [2] 98 62 [2] 8f 69 [2] 94 27 [2] a9 }

  condition:
    any of them
}