rule TTP_XOR_WriteProcessMemory_5865 {
  strings:
    $key_5865 = { 0f 17 [2] 3d 35 [2] 3b 00 [2] 15 00 [2] 2a 1c }

  condition:
    any of them
}