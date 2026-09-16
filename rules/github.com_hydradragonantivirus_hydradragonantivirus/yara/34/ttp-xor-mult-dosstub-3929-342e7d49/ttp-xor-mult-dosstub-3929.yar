rule TTP_XOR_MULT_DOSStub_3929 {
  strings:
    $key_3929 = { 6d 41 [2] 19 59 [2] 5e 5b [2] 19 4a [2] 57 46 [2] 5b 4c [2] 4c 47 [2] 57 09 [2] 6a }

  condition:
    any of them
}