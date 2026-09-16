rule TTP_XOR_MULT_DOSStub_3923 {
  strings:
    $key_3923 = { 6d 4b [2] 19 53 [2] 5e 51 [2] 19 40 [2] 57 4c [2] 5b 46 [2] 4c 4d [2] 57 03 [2] 6a }

  condition:
    any of them
}