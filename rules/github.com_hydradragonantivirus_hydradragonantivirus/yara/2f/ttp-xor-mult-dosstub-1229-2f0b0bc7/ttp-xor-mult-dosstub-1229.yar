rule TTP_XOR_MULT_DOSStub_1229 {
  strings:
    $key_1229 = { 46 41 [2] 32 59 [2] 75 5b [2] 32 4a [2] 7c 46 [2] 70 4c [2] 67 47 [2] 7c 09 [2] 41 }

  condition:
    any of them
}