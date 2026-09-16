rule TTP_XOR_WriteProcessMemory_0735 {
  strings:
    $key_0735 = { 50 47 [2] 62 65 [2] 64 50 [2] 4a 50 [2] 75 4c }

  condition:
    any of them
}