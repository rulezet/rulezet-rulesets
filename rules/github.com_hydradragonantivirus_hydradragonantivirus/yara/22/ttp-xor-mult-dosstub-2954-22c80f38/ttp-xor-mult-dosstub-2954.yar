rule TTP_XOR_MULT_DOSStub_2954 {
  strings:
    $key_2954 = { 7d 3c [2] 09 24 [2] 4e 26 [2] 09 37 [2] 47 3b [2] 4b 31 [2] 5c 3a [2] 47 74 [2] 7a }

  condition:
    any of them
}