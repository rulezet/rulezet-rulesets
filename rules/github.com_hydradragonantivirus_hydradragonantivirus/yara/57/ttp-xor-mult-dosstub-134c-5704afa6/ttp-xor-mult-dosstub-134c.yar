rule TTP_XOR_MULT_DOSStub_134c {
  strings:
    $key_134c = { 47 24 [2] 33 3c [2] 74 3e [2] 33 2f [2] 7d 23 [2] 71 29 [2] 66 22 [2] 7d 6c [2] 40 }

  condition:
    any of them
}