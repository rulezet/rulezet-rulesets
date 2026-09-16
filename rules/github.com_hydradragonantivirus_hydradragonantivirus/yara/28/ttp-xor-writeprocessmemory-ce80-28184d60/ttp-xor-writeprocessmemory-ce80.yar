rule TTP_XOR_WriteProcessMemory_ce80 {
  strings:
    $key_ce80 = { 99 f2 [2] ab d0 [2] ad e5 [2] 83 e5 [2] bc f9 }

  condition:
    any of them
}