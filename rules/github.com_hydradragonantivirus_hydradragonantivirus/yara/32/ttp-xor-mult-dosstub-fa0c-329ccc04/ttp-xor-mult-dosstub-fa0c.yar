rule TTP_XOR_MULT_DOSStub_fa0c {
  strings:
    $key_fa0c = { ae 64 [2] da 7c [2] 9d 7e [2] da 6f [2] 94 63 [2] 98 69 [2] 8f 62 [2] 94 2c [2] a9 }

  condition:
    any of them
}