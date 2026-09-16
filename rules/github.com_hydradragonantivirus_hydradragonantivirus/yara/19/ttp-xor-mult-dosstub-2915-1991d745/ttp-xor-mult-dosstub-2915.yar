rule TTP_XOR_MULT_DOSStub_2915 {
  strings:
    $key_2915 = { 7d 7d [2] 09 65 [2] 4e 67 [2] 09 76 [2] 47 7a [2] 4b 70 [2] 5c 7b [2] 47 35 [2] 7a }

  condition:
    any of them
}