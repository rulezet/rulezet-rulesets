rule TTP_XOR_MULT_DOSStub_333c {
  strings:
    $key_333c = { 67 54 [2] 13 4c [2] 54 4e [2] 13 5f [2] 5d 53 [2] 51 59 [2] 46 52 [2] 5d 1c [2] 60 }

  condition:
    any of them
}