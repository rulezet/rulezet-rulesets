rule TTP_XOR_MULT_DOSStub_0651 {
  strings:
    $key_0651 = { 52 39 [2] 26 21 [2] 61 23 [2] 26 32 [2] 68 3e [2] 64 34 [2] 73 3f [2] 68 71 [2] 55 }

  condition:
    any of them
}