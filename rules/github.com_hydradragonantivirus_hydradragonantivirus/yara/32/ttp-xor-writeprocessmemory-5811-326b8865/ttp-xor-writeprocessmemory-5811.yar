rule TTP_XOR_WriteProcessMemory_5811 {
  strings:
    $key_5811 = { 0f 63 [2] 3d 41 [2] 3b 74 [2] 15 74 [2] 2a 68 }

  condition:
    any of them
}