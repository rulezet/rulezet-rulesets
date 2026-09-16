rule TTP_XOR_MULT_DOSStub_2969 {
  strings:
    $key_2969 = { 7d 01 [2] 09 19 [2] 4e 1b [2] 09 0a [2] 47 06 [2] 4b 0c [2] 5c 07 [2] 47 49 [2] 7a }

  condition:
    any of them
}