rule TTP_XOR_WriteProcessMemory_3621 {
  strings:
    $key_3621 = { 61 53 [2] 53 71 [2] 55 44 [2] 7b 44 [2] 44 58 }

  condition:
    any of them
}