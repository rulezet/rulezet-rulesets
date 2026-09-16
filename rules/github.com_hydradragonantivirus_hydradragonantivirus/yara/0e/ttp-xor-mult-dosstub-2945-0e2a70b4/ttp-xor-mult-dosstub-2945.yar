rule TTP_XOR_MULT_DOSStub_2945 {
  strings:
    $key_2945 = { 7d 2d [2] 09 35 [2] 4e 37 [2] 09 26 [2] 47 2a [2] 4b 20 [2] 5c 2b [2] 47 65 [2] 7a }

  condition:
    any of them
}