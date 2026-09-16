rule TTP_XOR_MULT_DOSStub_343c {
  strings:
    $key_343c = { 60 54 [2] 14 4c [2] 53 4e [2] 14 5f [2] 5a 53 [2] 56 59 [2] 41 52 [2] 5a 1c [2] 67 }

  condition:
    any of them
}