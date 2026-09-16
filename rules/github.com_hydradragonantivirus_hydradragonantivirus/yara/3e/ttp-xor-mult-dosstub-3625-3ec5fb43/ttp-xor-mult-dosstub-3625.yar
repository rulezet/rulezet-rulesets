rule TTP_XOR_MULT_DOSStub_3625 {
  strings:
    $key_3625 = { 62 4d [2] 16 55 [2] 51 57 [2] 16 46 [2] 58 4a [2] 54 40 [2] 43 4b [2] 58 05 [2] 65 }

  condition:
    any of them
}