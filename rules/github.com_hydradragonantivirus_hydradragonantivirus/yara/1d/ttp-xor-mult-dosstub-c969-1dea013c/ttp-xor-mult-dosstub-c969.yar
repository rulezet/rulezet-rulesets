rule TTP_XOR_MULT_DOSStub_c969 {
  strings:
    $key_c969 = { 9d 01 [2] e9 19 [2] ae 1b [2] e9 0a [2] a7 06 [2] ab 0c [2] bc 07 [2] a7 49 [2] 9a }

  condition:
    any of them
}