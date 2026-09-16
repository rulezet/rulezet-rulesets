rule TTP_XOR_MULT_DOSStub_2979 {
  strings:
    $key_2979 = { 7d 11 [2] 09 09 [2] 4e 0b [2] 09 1a [2] 47 16 [2] 4b 1c [2] 5c 17 [2] 47 59 [2] 7a }

  condition:
    any of them
}