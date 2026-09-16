rule TTP_XOR_MULT_DOSStub_2629 {
  strings:
    $key_2629 = { 72 41 [2] 06 59 [2] 41 5b [2] 06 4a [2] 48 46 [2] 44 4c [2] 53 47 [2] 48 09 [2] 75 }

  condition:
    any of them
}