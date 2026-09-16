rule TTP_XOR_MULT_DOSStub_fa0b {
  strings:
    $key_fa0b = { ae 63 [2] da 7b [2] 9d 79 [2] da 68 [2] 94 64 [2] 98 6e [2] 8f 65 [2] 94 2b [2] a9 }

  condition:
    any of them
}