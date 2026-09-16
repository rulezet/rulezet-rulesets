rule TTP_XOR_MULT_DOSStub_15bf {
  strings:
    $key_15bf = { 41 d7 [2] 35 cf [2] 72 cd [2] 35 dc [2] 7b d0 [2] 77 da [2] 60 d1 [2] 7b 9f [2] 46 }

  condition:
    any of them
}