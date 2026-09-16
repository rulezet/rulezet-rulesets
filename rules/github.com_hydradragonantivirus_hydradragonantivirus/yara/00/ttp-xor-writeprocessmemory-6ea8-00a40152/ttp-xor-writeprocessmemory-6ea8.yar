rule TTP_XOR_WriteProcessMemory_6ea8 {
  strings:
    $key_6ea8 = { 39 da [2] 0b f8 [2] 0d cd [2] 23 cd [2] 1c d1 }

  condition:
    any of them
}