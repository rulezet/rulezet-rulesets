rule TTP_XOR_MULT_DOSStub_db93 {
  strings:
    $key_db93 = { 8f fb [2] fb e3 [2] bc e1 [2] fb f0 [2] b5 fc [2] b9 f6 [2] ae fd [2] b5 b3 [2] 88 }

  condition:
    any of them
}