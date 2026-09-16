rule TTP_XOR_MULT_DOSStub_2963 {
  strings:
    $key_2963 = { 7d 0b [2] 09 13 [2] 4e 11 [2] 09 00 [2] 47 0c [2] 4b 06 [2] 5c 0d [2] 47 43 [2] 7a }

  condition:
    any of them
}