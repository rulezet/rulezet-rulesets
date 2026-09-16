rule TTP_XOR_MULT_DOSStub_e37b {
  strings:
    $key_e37b = { b7 13 [2] c3 0b [2] 84 09 [2] c3 18 [2] 8d 14 [2] 81 1e [2] 96 15 [2] 8d 5b [2] b0 }

  condition:
    any of them
}