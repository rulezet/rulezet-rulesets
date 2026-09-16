rule TTP_XOR_MULT_DOSStub_619e {
  strings:
    $key_619e = { 35 f6 [2] 41 ee [2] 06 ec [2] 41 fd [2] 0f f1 [2] 03 fb [2] 14 f0 [2] 0f be [2] 32 }

  condition:
    any of them
}