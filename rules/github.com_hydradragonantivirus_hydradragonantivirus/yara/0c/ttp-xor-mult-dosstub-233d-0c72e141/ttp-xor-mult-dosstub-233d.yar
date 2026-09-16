rule TTP_XOR_MULT_DOSStub_233d {
  strings:
    $key_233d = { 77 55 [2] 03 4d [2] 44 4f [2] 03 5e [2] 4d 52 [2] 41 58 [2] 56 53 [2] 4d 1d [2] 70 }

  condition:
    any of them
}