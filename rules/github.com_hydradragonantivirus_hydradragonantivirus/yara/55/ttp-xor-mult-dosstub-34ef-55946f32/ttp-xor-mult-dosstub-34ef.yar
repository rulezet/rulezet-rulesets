rule TTP_XOR_MULT_DOSStub_34ef {
  strings:
    $key_34ef = { 60 87 [2] 14 9f [2] 53 9d [2] 14 8c [2] 5a 80 [2] 56 8a [2] 41 81 [2] 5a cf [2] 67 }

  condition:
    any of them
}