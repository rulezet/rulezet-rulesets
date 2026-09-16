rule TTP_XOR_WriteProcessMemory_7ea8 {
  strings:
    $key_7ea8 = { 29 da [2] 1b f8 [2] 1d cd [2] 33 cd [2] 0c d1 }

  condition:
    any of them
}