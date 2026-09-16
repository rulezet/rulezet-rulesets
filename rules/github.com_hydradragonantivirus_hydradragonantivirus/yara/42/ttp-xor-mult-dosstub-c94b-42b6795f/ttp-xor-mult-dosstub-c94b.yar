rule TTP_XOR_MULT_DOSStub_c94b {
  strings:
    $key_c94b = { 9d 23 [2] e9 3b [2] ae 39 [2] e9 28 [2] a7 24 [2] ab 2e [2] bc 25 [2] a7 6b [2] 9a }

  condition:
    any of them
}