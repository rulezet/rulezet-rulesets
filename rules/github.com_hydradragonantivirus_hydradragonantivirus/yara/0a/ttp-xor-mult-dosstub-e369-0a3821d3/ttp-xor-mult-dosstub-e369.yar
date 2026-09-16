rule TTP_XOR_MULT_DOSStub_e369 {
  strings:
    $key_e369 = { b7 01 [2] c3 19 [2] 84 1b [2] c3 0a [2] 8d 06 [2] 81 0c [2] 96 07 [2] 8d 49 [2] b0 }

  condition:
    any of them
}