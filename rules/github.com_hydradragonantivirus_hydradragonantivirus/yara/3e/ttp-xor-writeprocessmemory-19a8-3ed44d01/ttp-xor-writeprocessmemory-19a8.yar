rule TTP_XOR_WriteProcessMemory_19a8 {
  strings:
    $key_19a8 = { 4e da [2] 7c f8 [2] 7a cd [2] 54 cd [2] 6b d1 }

  condition:
    any of them
}