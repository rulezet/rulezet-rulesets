rule TTP_XOR_WriteProcessMemory_5827 {
  strings:
    $key_5827 = { 0f 55 [2] 3d 77 [2] 3b 42 [2] 15 42 [2] 2a 5e }

  condition:
    any of them
}