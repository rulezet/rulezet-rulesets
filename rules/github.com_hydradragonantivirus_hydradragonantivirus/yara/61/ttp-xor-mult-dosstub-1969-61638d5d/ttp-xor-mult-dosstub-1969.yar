rule TTP_XOR_MULT_DOSStub_1969 {
  strings:
    $key_1969 = { 4d 01 [2] 39 19 [2] 7e 1b [2] 39 0a [2] 77 06 [2] 7b 0c [2] 6c 07 [2] 77 49 [2] 4a }

  condition:
    any of them
}