rule TTP_XOR_WriteProcessMemory_ce82 {
  strings:
    $key_ce82 = { 99 f0 [2] ab d2 [2] ad e7 [2] 83 e7 [2] bc fb }

  condition:
    any of them
}