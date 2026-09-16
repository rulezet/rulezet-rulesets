rule TTP_XOR_WriteProcessMemory_1647 {
  strings:
    $key_1647 = { 41 35 [2] 73 17 [2] 75 22 [2] 5b 22 [2] 64 3e }

  condition:
    any of them
}