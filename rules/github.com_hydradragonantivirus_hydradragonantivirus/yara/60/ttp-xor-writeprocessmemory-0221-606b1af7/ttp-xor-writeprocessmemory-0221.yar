rule TTP_XOR_WriteProcessMemory_0221 {
  strings:
    $key_0221 = { 55 53 [2] 67 71 [2] 61 44 [2] 4f 44 [2] 70 58 }

  condition:
    any of them
}