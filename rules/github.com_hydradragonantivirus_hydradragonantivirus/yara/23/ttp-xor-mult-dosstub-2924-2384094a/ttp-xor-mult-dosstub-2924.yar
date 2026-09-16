rule TTP_XOR_MULT_DOSStub_2924 {
  strings:
    $key_2924 = { 7d 4c [2] 09 54 [2] 4e 56 [2] 09 47 [2] 47 4b [2] 4b 41 [2] 5c 4a [2] 47 04 [2] 7a }

  condition:
    any of them
}