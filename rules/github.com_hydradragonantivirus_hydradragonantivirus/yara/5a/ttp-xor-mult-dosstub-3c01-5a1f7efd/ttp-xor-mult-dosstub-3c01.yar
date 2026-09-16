rule TTP_XOR_MULT_DOSStub_3c01 {
  strings:
    $key_3c01 = { 68 69 [2] 1c 71 [2] 5b 73 [2] 1c 62 [2] 52 6e [2] 5e 64 [2] 49 6f [2] 52 21 [2] 6f }

  condition:
    any of them
}