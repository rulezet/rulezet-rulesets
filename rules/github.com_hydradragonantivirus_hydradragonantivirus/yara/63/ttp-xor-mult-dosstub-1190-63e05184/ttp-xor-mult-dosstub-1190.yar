rule TTP_XOR_MULT_DOSStub_1190 {
  strings:
    $key_1190 = { 45 f8 [2] 31 e0 [2] 76 e2 [2] 31 f3 [2] 7f ff [2] 73 f5 [2] 64 fe [2] 7f b0 [2] 42 }

  condition:
    any of them
}