rule TTP_XOR_MULT_DOSStub_233c {
  strings:
    $key_233c = { 77 54 [2] 03 4c [2] 44 4e [2] 03 5f [2] 4d 53 [2] 41 59 [2] 56 52 [2] 4d 1c [2] 70 }

  condition:
    any of them
}