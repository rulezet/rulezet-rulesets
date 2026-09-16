rule TTP_XOR_MULT_DOSStub_e301 {
  strings:
    $key_e301 = { b7 69 [2] c3 71 [2] 84 73 [2] c3 62 [2] 8d 6e [2] 81 64 [2] 96 6f [2] 8d 21 [2] b0 }

  condition:
    any of them
}