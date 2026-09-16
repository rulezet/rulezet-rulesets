rule TTP_XOR_WriteProcessMemory_e9a8 {
  strings:
    $key_e9a8 = { be da [2] 8c f8 [2] 8a cd [2] a4 cd [2] 9b d1 }

  condition:
    any of them
}