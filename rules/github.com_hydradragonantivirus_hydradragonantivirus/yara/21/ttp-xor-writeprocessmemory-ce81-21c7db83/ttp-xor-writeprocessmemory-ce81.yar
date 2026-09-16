rule TTP_XOR_WriteProcessMemory_ce81 {
  strings:
    $key_ce81 = { 99 f3 [2] ab d1 [2] ad e4 [2] 83 e4 [2] bc f8 }

  condition:
    any of them
}