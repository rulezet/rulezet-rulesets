rule TTP_XOR_MULT_DOSStub_defb {
  strings:
    $key_defb = { 8a 93 [2] fe 8b [2] b9 89 [2] fe 98 [2] b0 94 [2] bc 9e [2] ab 95 [2] b0 db [2] 8d }

  condition:
    any of them
}