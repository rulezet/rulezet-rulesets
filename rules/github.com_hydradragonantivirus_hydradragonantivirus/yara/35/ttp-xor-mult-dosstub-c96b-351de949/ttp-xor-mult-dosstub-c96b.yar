rule TTP_XOR_MULT_DOSStub_c96b {
  strings:
    $key_c96b = { 9d 03 [2] e9 1b [2] ae 19 [2] e9 08 [2] a7 04 [2] ab 0e [2] bc 05 [2] a7 4b [2] 9a }

  condition:
    any of them
}