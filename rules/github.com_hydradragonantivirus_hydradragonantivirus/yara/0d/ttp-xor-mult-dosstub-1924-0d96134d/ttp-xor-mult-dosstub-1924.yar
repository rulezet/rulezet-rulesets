rule TTP_XOR_MULT_DOSStub_1924 {
  strings:
    $key_1924 = { 4d 4c [2] 39 54 [2] 7e 56 [2] 39 47 [2] 77 4b [2] 7b 41 [2] 6c 4a [2] 77 04 [2] 4a }

  condition:
    any of them
}