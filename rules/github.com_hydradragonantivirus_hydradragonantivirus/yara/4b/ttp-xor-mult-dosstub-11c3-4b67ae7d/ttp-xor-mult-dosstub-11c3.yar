rule TTP_XOR_MULT_DOSStub_11c3 {
  strings:
    $key_11c3 = { 45 ab [2] 31 b3 [2] 76 b1 [2] 31 a0 [2] 7f ac [2] 73 a6 [2] 64 ad [2] 7f e3 [2] 42 }

  condition:
    any of them
}