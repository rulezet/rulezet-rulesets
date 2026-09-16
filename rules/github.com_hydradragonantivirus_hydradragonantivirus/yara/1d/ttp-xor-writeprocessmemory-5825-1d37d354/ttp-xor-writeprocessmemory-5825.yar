rule TTP_XOR_WriteProcessMemory_5825 {
  strings:
    $key_5825 = { 0f 57 [2] 3d 75 [2] 3b 40 [2] 15 40 [2] 2a 5c }

  condition:
    any of them
}