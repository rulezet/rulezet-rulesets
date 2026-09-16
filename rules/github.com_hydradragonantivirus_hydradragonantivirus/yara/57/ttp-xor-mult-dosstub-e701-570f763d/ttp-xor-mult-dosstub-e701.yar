rule TTP_XOR_MULT_DOSStub_e701 {
  strings:
    $key_e701 = { b3 69 [2] c7 71 [2] 80 73 [2] c7 62 [2] 89 6e [2] 85 64 [2] 92 6f [2] 89 21 [2] b4 }

  condition:
    any of them
}