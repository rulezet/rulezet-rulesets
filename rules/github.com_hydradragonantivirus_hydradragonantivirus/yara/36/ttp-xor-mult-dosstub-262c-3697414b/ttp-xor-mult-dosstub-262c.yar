rule TTP_XOR_MULT_DOSStub_262c {
  strings:
    $key_262c = { 72 44 [2] 06 5c [2] 41 5e [2] 06 4f [2] 48 43 [2] 44 49 [2] 53 42 [2] 48 0c [2] 75 }

  condition:
    any of them
}