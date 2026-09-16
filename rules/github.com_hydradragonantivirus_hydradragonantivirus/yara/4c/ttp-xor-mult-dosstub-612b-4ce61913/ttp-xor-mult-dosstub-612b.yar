rule TTP_XOR_MULT_DOSStub_612b {
  strings:
    $key_612b = { 35 43 [2] 41 5b [2] 06 59 [2] 41 48 [2] 0f 44 [2] 03 4e [2] 14 45 [2] 0f 0b [2] 32 }

  condition:
    any of them
}