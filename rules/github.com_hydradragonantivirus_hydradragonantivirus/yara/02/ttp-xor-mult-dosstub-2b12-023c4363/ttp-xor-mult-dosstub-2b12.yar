rule TTP_XOR_MULT_DOSStub_2b12 {
  strings:
    $key_2b12 = { 7f 7a [2] 0b 62 [2] 4c 60 [2] 0b 71 [2] 45 7d [2] 49 77 [2] 5e 7c [2] 45 32 [2] 78 }

  condition:
    any of them
}