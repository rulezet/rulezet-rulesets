rule TTP_XOR_WriteProcessMemory_d9aa {
  strings:
    $key_d9aa = { 8e d8 [2] bc fa [2] ba cf [2] 94 cf [2] ab d3 }

  condition:
    any of them
}