rule TTP_XOR_MULT_DOSStub_43ef {
  strings:
    $key_43ef = { 17 87 [2] 63 9f [2] 24 9d [2] 63 8c [2] 2d 80 [2] 21 8a [2] 36 81 [2] 2d cf [2] 10 }

  condition:
    any of them
}