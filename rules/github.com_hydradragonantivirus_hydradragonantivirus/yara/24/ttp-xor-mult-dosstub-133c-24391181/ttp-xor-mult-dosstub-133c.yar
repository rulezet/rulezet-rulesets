rule TTP_XOR_MULT_DOSStub_133c {
  strings:
    $key_133c = { 47 54 [2] 33 4c [2] 74 4e [2] 33 5f [2] 7d 53 [2] 71 59 [2] 66 52 [2] 7d 1c [2] 40 }

  condition:
    any of them
}