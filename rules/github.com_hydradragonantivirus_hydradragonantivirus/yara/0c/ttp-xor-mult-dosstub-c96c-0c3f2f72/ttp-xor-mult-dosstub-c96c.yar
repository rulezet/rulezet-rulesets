rule TTP_XOR_MULT_DOSStub_c96c {
  strings:
    $key_c96c = { 9d 04 [2] e9 1c [2] ae 1e [2] e9 0f [2] a7 03 [2] ab 09 [2] bc 02 [2] a7 4c [2] 9a }

  condition:
    any of them
}