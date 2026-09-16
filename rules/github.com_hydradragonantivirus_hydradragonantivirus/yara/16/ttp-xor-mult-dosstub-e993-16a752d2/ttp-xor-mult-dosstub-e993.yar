rule TTP_XOR_MULT_DOSStub_e993 {
  strings:
    $key_e993 = { bd fb [2] c9 e3 [2] 8e e1 [2] c9 f0 [2] 87 fc [2] 8b f6 [2] 9c fd [2] 87 b3 [2] ba }

  condition:
    any of them
}