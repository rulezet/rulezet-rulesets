rule TTP_XOR_MULT_DOSStub_263b {
  strings:
    $key_263b = { 72 53 [2] 06 4b [2] 41 49 [2] 06 58 [2] 48 54 [2] 44 5e [2] 53 55 [2] 48 1b [2] 75 }

  condition:
    any of them
}