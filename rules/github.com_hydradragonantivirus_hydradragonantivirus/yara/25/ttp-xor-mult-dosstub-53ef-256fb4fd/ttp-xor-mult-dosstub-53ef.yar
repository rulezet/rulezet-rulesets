rule TTP_XOR_MULT_DOSStub_53ef {
  strings:
    $key_53ef = { 07 87 [2] 73 9f [2] 34 9d [2] 73 8c [2] 3d 80 [2] 31 8a [2] 26 81 [2] 3d cf [2] 00 }

  condition:
    any of them
}