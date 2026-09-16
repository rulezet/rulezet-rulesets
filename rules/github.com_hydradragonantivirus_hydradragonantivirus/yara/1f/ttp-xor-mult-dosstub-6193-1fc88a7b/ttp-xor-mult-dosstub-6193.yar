rule TTP_XOR_MULT_DOSStub_6193 {
  strings:
    $key_6193 = { 35 fb [2] 41 e3 [2] 06 e1 [2] 41 f0 [2] 0f fc [2] 03 f6 [2] 14 fd [2] 0f b3 [2] 32 }

  condition:
    any of them
}