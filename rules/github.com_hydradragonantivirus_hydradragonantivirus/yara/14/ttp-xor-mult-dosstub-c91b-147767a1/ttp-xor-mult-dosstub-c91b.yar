rule TTP_XOR_MULT_DOSStub_c91b {
  strings:
    $key_c91b = { 9d 73 [2] e9 6b [2] ae 69 [2] e9 78 [2] a7 74 [2] ab 7e [2] bc 75 [2] a7 3b [2] 9a }

  condition:
    any of them
}