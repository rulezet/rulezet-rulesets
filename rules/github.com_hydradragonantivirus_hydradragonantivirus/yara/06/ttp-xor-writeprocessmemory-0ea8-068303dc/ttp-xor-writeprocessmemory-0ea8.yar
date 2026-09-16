rule TTP_XOR_WriteProcessMemory_0ea8 {
  strings:
    $key_0ea8 = { 59 da [2] 6b f8 [2] 6d cd [2] 43 cd [2] 7c d1 }

  condition:
    any of them
}