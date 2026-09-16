rule TTP_XOR_MULT_DOSStub_2993 {
  strings:
    $key_2993 = { 7d fb [2] 09 e3 [2] 4e e1 [2] 09 f0 [2] 47 fc [2] 4b f6 [2] 5c fd [2] 47 b3 [2] 7a }

  condition:
    any of them
}