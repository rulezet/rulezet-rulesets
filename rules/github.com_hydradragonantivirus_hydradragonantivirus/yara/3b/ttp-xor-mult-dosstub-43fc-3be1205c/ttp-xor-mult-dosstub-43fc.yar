rule TTP_XOR_MULT_DOSStub_43fc {
  strings:
    $key_43fc = { 17 94 [2] 63 8c [2] 24 8e [2] 63 9f [2] 2d 93 [2] 21 99 [2] 36 92 [2] 2d dc [2] 10 }

  condition:
    any of them
}