rule TTP_XOR_MULT_DOSStub_6173 {
  strings:
    $key_6173 = { 35 1b [2] 41 03 [2] 06 01 [2] 41 10 [2] 0f 1c [2] 03 16 [2] 14 1d [2] 0f 53 [2] 32 }

  condition:
    any of them
}