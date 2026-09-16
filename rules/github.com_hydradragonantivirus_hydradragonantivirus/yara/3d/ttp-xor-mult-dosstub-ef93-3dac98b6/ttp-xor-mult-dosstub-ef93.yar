rule TTP_XOR_MULT_DOSStub_ef93 {
  strings:
    $key_ef93 = { bb fb [2] cf e3 [2] 88 e1 [2] cf f0 [2] 81 fc [2] 8d f6 [2] 9a fd [2] 81 b3 [2] bc }

  condition:
    any of them
}