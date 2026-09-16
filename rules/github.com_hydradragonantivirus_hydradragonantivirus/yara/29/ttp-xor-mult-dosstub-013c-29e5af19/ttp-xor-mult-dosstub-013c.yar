rule TTP_XOR_MULT_DOSStub_013c {
  strings:
    $key_013c = { 55 54 [2] 21 4c [2] 66 4e [2] 21 5f [2] 6f 53 [2] 63 59 [2] 74 52 [2] 6f 1c [2] 52 }

  condition:
    any of them
}