rule TTP_XOR_MULT_DOSStub_573c {
  strings:
    $key_573c = { 03 54 [2] 77 4c [2] 30 4e [2] 77 5f [2] 39 53 [2] 35 59 [2] 22 52 [2] 39 1c [2] 04 }

  condition:
    any of them
}