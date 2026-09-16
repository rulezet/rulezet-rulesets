rule TTP_XOR_MULT_DOSStub_1963 {
  strings:
    $key_1963 = { 4d 0b [2] 39 13 [2] 7e 11 [2] 39 00 [2] 77 0c [2] 7b 06 [2] 6c 0d [2] 77 43 [2] 4a }

  condition:
    any of them
}