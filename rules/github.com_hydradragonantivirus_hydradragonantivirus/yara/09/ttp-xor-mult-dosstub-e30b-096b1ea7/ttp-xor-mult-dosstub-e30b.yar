rule TTP_XOR_MULT_DOSStub_e30b {
  strings:
    $key_e30b = { b7 63 [2] c3 7b [2] 84 79 [2] c3 68 [2] 8d 64 [2] 81 6e [2] 96 65 [2] 8d 2b [2] b0 }

  condition:
    any of them
}