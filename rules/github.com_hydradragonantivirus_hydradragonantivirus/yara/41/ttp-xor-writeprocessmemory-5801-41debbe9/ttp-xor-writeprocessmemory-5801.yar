rule TTP_XOR_WriteProcessMemory_5801 {
  strings:
    $key_5801 = { 0f 73 [2] 3d 51 [2] 3b 64 [2] 15 64 [2] 2a 78 }

  condition:
    any of them
}