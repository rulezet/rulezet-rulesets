rule TTP_XOR_MULT_DOSStub_657c {
  strings:
    $key_657c = { 31 14 [2] 45 0c [2] 02 0e [2] 45 1f [2] 0b 13 [2] 07 19 [2] 10 12 [2] 0b 5c [2] 36 }

  condition:
    any of them
}