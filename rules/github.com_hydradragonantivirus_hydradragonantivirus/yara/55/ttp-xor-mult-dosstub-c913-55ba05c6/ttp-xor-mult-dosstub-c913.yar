rule TTP_XOR_MULT_DOSStub_c913 {
  strings:
    $key_c913 = { 9d 7b [2] e9 63 [2] ae 61 [2] e9 70 [2] a7 7c [2] ab 76 [2] bc 7d [2] a7 33 [2] 9a }

  condition:
    any of them
}