rule TTP_XOR_MULT_DOSStub_e31b {
  strings:
    $key_e31b = { b7 73 [2] c3 6b [2] 84 69 [2] c3 78 [2] 8d 74 [2] 81 7e [2] 96 75 [2] 8d 3b [2] b0 }

  condition:
    any of them
}