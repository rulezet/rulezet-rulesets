rule TTP_XOR_MULT_DOSStub_613b {
  strings:
    $key_613b = { 35 53 [2] 41 4b [2] 06 49 [2] 41 58 [2] 0f 54 [2] 03 5e [2] 14 55 [2] 0f 1b [2] 32 }

  condition:
    any of them
}