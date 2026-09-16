rule TTP_XOR_WriteProcessMemory_2245 {
  strings:
    $key_2245 = { 75 37 [2] 47 15 [2] 41 20 [2] 6f 20 [2] 50 3c }

  condition:
    any of them
}