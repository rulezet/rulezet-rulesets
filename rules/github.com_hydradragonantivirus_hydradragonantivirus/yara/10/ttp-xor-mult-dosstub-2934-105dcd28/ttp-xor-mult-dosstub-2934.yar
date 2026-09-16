rule TTP_XOR_MULT_DOSStub_2934 {
  strings:
    $key_2934 = { 7d 5c [2] 09 44 [2] 4e 46 [2] 09 57 [2] 47 5b [2] 4b 51 [2] 5c 5a [2] 47 14 [2] 7a }

  condition:
    any of them
}