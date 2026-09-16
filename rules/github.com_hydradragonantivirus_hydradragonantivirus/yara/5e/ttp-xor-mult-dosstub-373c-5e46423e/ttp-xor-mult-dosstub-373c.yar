rule TTP_XOR_MULT_DOSStub_373c {
  strings:
    $key_373c = { 63 54 [2] 17 4c [2] 50 4e [2] 17 5f [2] 59 53 [2] 55 59 [2] 42 52 [2] 59 1c [2] 64 }

  condition:
    any of them
}