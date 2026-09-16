rule TTP_XOR_MULT_DOSStub_2bf5 {
  strings:
    $key_2bf5 = { 7f 9d [2] 0b 85 [2] 4c 87 [2] 0b 96 [2] 45 9a [2] 49 90 [2] 5e 9b [2] 45 d5 [2] 78 }

  condition:
    any of them
}