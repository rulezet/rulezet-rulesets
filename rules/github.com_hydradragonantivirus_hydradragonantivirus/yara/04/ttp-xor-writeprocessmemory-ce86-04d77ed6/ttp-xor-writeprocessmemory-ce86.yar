rule TTP_XOR_WriteProcessMemory_ce86 {
  strings:
    $key_ce86 = { 99 f4 [2] ab d6 [2] ad e3 [2] 83 e3 [2] bc ff }

  condition:
    any of them
}