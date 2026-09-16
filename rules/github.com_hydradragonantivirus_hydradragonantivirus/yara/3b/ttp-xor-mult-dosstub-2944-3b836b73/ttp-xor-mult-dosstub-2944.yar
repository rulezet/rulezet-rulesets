rule TTP_XOR_MULT_DOSStub_2944 {
  strings:
    $key_2944 = { 7d 2c [2] 09 34 [2] 4e 36 [2] 09 27 [2] 47 2b [2] 4b 21 [2] 5c 2a [2] 47 64 [2] 7a }

  condition:
    any of them
}