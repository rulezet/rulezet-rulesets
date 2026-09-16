rule TTP_XOR_MULT_DOSStub_c9a8 {
  strings:
    $key_c9a8 = { 9d c0 [2] e9 d8 [2] ae da [2] e9 cb [2] a7 c7 [2] ab cd [2] bc c6 [2] a7 88 [2] 9a }

  condition:
    any of them
}