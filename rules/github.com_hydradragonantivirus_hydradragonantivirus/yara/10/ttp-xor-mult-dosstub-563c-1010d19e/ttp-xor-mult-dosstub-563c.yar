rule TTP_XOR_MULT_DOSStub_563c {
  strings:
    $key_563c = { 02 54 [2] 76 4c [2] 31 4e [2] 76 5f [2] 38 53 [2] 34 59 [2] 23 52 [2] 38 1c [2] 05 }

  condition:
    any of them
}