rule TTP_XOR_MULT_DOSStub_2949 {
  strings:
    $key_2949 = { 7d 21 [2] 09 39 [2] 4e 3b [2] 09 2a [2] 47 26 [2] 4b 2c [2] 5c 27 [2] 47 69 [2] 7a }

  condition:
    any of them
}