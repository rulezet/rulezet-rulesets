rule TTP_XOR_WriteProcessMemory_0a35 {
  strings:
    $key_0a35 = { 5d 47 [2] 6f 65 [2] 69 50 [2] 47 50 [2] 78 4c }

  condition:
    any of them
}