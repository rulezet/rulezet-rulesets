rule TTP_XOR_MULT_DOSStub_23ef {
  strings:
    $key_23ef = { 77 87 [2] 03 9f [2] 44 9d [2] 03 8c [2] 4d 80 [2] 41 8a [2] 56 81 [2] 4d cf [2] 70 }

  condition:
    any of them
}