rule TTP_XOR_WriteProcessMemory_ce85 {
  strings:
    $key_ce85 = { 99 f7 [2] ab d5 [2] ad e0 [2] 83 e0 [2] bc fc }

  condition:
    any of them
}