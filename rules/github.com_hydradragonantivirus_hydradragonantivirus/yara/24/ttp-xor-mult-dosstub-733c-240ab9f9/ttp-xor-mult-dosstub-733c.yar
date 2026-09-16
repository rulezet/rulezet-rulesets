rule TTP_XOR_MULT_DOSStub_733c {
  strings:
    $key_733c = { 27 54 [2] 53 4c [2] 14 4e [2] 53 5f [2] 1d 53 [2] 11 59 [2] 06 52 [2] 1d 1c [2] 20 }

  condition:
    any of them
}