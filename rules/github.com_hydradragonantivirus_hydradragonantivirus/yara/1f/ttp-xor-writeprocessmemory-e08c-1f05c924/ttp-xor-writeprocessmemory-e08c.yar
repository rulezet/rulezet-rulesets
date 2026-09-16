rule TTP_XOR_WriteProcessMemory_e08c {
  strings:
    $key_e08c = { b7 fe [2] 85 dc [2] 83 e9 [2] ad e9 [2] 92 f5 }

  condition:
    any of them
}