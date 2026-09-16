rule TTP_XOR_MULT_DOSStub_4902 {
  strings:
    $key_4902 = { 1d 6a [2] 69 72 [2] 2e 70 [2] 69 61 [2] 27 6d [2] 2b 67 [2] 3c 6c [2] 27 22 [2] 1a }

  condition:
    any of them
}