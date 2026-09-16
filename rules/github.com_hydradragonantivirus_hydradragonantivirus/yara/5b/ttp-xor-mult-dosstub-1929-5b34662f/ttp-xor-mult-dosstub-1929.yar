rule TTP_XOR_MULT_DOSStub_1929 {
  strings:
    $key_1929 = { 4d 41 [2] 39 59 [2] 7e 5b [2] 39 4a [2] 77 46 [2] 7b 4c [2] 6c 47 [2] 77 09 [2] 4a }

  condition:
    any of them
}