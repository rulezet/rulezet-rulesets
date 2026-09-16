rule TTP_XOR_MULT_DOSStub_3902 {
  strings:
    $key_3902 = { 6d 6a [2] 19 72 [2] 5e 70 [2] 19 61 [2] 57 6d [2] 5b 67 [2] 4c 6c [2] 57 22 [2] 6a }

  condition:
    any of them
}