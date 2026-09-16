rule TTP_XOR_MULT_DOSStub_c903 {
  strings:
    $key_c903 = { 9d 6b [2] e9 73 [2] ae 71 [2] e9 60 [2] a7 6c [2] ab 66 [2] bc 6d [2] a7 23 [2] 9a }

  condition:
    any of them
}