rule TTP_XOR_MULT_DOSStub_232b {
  strings:
    $key_232b = { 77 43 [2] 03 5b [2] 44 59 [2] 03 48 [2] 4d 44 [2] 41 4e [2] 56 45 [2] 4d 0b [2] 70 }

  condition:
    any of them
}