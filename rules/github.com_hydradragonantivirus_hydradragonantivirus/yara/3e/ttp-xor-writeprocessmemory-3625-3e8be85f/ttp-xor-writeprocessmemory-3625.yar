rule TTP_XOR_WriteProcessMemory_3625 {
  strings:
    $key_3625 = { 61 57 [2] 53 75 [2] 55 40 [2] 7b 40 [2] 44 5c }

  condition:
    any of them
}