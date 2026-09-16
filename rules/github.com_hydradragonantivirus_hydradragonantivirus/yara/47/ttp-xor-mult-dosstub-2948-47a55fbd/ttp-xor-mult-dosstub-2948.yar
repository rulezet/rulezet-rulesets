rule TTP_XOR_MULT_DOSStub_2948 {
  strings:
    $key_2948 = { 7d 20 [2] 09 38 [2] 4e 3a [2] 09 2b [2] 47 27 [2] 4b 2d [2] 5c 26 [2] 47 68 [2] 7a }

  condition:
    any of them
}