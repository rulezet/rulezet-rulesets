rule TTP_XOR_MULT_DOSStub_33ef {
  strings:
    $key_33ef = { 67 87 [2] 13 9f [2] 54 9d [2] 13 8c [2] 5d 80 [2] 51 8a [2] 46 81 [2] 5d cf [2] 60 }

  condition:
    any of them
}