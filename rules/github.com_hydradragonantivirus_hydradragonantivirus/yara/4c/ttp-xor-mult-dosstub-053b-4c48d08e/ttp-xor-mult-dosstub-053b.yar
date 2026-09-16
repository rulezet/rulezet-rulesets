rule TTP_XOR_MULT_DOSStub_053b {
  strings:
    $key_053b = { 51 53 [2] 25 4b [2] 62 49 [2] 25 58 [2] 6b 54 [2] 67 5e [2] 70 55 [2] 6b 1b [2] 56 }

  condition:
    any of them
}