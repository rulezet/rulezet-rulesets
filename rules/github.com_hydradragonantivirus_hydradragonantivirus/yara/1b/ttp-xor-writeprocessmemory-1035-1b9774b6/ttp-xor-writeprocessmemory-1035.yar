rule TTP_XOR_WriteProcessMemory_1035 {
  strings:
    $key_1035 = { 47 47 [2] 75 65 [2] 73 50 [2] 5d 50 [2] 62 4c }

  condition:
    any of them
}