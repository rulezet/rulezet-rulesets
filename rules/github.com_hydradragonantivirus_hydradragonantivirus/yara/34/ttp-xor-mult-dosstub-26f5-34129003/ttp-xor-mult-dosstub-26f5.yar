rule TTP_XOR_MULT_DOSStub_26f5 {
  strings:
    $key_26f5 = { 72 9d [2] 06 85 [2] 41 87 [2] 06 96 [2] 48 9a [2] 44 90 [2] 53 9b [2] 48 d5 [2] 75 }

  condition:
    any of them
}