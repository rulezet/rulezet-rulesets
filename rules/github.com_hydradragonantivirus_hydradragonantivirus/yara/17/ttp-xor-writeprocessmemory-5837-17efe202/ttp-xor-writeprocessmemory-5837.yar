rule TTP_XOR_WriteProcessMemory_5837 {
  strings:
    $key_5837 = { 0f 45 [2] 3d 67 [2] 3b 52 [2] 15 52 [2] 2a 4e }

  condition:
    any of them
}