rule TTP_XOR_WriteProcessMemory_5822 {
  strings:
    $key_5822 = { 0f 50 [2] 3d 72 [2] 3b 47 [2] 15 47 [2] 2a 5b }

  condition:
    any of them
}