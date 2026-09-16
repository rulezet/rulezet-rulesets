rule TTP_XOR_WriteProcessMemory_bea5 {
  strings:
    $key_bea5 = { e9 d7 [2] db f5 [2] dd c0 [2] f3 c0 [2] cc dc }

  condition:
    any of them
}