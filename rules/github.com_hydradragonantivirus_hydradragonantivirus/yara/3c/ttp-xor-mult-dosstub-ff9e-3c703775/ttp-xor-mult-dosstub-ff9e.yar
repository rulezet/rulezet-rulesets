rule TTP_XOR_MULT_DOSStub_ff9e {
  strings:
    $key_ff9e = { ab f6 [2] df ee [2] 98 ec [2] df fd [2] 91 f1 [2] 9d fb [2] 8a f0 [2] 91 be [2] ac }

  condition:
    any of them
}