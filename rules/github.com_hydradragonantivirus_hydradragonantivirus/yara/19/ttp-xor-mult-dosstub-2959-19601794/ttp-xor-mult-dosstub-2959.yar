rule TTP_XOR_MULT_DOSStub_2959 {
  strings:
    $key_2959 = { 7d 31 [2] 09 29 [2] 4e 2b [2] 09 3a [2] 47 36 [2] 4b 3c [2] 5c 37 [2] 47 79 [2] 7a }

  condition:
    any of them
}