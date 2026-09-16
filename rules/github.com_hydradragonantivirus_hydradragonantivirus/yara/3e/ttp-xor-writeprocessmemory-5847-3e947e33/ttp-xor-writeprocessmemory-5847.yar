rule TTP_XOR_WriteProcessMemory_5847 {
  strings:
    $key_5847 = { 0f 35 [2] 3d 17 [2] 3b 22 [2] 15 22 [2] 2a 3e }

  condition:
    any of them
}