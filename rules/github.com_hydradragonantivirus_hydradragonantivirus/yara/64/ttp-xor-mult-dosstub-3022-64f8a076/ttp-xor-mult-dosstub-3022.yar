rule TTP_XOR_MULT_DOSStub_3022 {
  strings:
    $key_3022 = { 64 4a [2] 10 52 [2] 57 50 [2] 10 41 [2] 5e 4d [2] 52 47 [2] 45 4c [2] 5e 02 [2] 63 }

  condition:
    any of them
}