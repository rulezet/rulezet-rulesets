rule TTP_XOR_MULT_DOSStub_5229 {
  strings:
    $key_5229 = { 06 41 [2] 72 59 [2] 35 5b [2] 72 4a [2] 3c 46 [2] 30 4c [2] 27 47 [2] 3c 09 [2] 01 }

  condition:
    any of them
}