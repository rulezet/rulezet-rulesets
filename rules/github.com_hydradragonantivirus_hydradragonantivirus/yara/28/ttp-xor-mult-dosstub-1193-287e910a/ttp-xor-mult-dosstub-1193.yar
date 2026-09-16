rule TTP_XOR_MULT_DOSStub_1193 {
  strings:
    $key_1193 = { 45 fb [2] 31 e3 [2] 76 e1 [2] 31 f0 [2] 7f fc [2] 73 f6 [2] 64 fd [2] 7f b3 [2] 42 }

  condition:
    any of them
}