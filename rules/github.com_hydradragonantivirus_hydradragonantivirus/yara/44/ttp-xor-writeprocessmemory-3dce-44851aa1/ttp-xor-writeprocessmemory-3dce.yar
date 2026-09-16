rule TTP_XOR_WriteProcessMemory_3dce {
  strings:
    $key_3dce = { 6a bc [2] 58 9e [2] 5e ab [2] 70 ab [2] 4f b7 }

  condition:
    any of them
}