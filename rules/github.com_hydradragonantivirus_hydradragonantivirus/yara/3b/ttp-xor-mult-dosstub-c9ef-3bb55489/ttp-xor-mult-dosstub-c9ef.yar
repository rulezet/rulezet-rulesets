rule TTP_XOR_MULT_DOSStub_c9ef {
  strings:
    $key_c9ef = { 9d 87 [2] e9 9f [2] ae 9d [2] e9 8c [2] a7 80 [2] ab 8a [2] bc 81 [2] a7 cf [2] 9a }

  condition:
    any of them
}