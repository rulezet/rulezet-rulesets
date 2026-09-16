rule TTP_XOR_MULT_DOSStub_c993 {
  strings:
    $key_c993 = { 9d fb [2] e9 e3 [2] ae e1 [2] e9 f0 [2] a7 fc [2] ab f6 [2] bc fd [2] a7 b3 [2] 9a }

  condition:
    any of them
}