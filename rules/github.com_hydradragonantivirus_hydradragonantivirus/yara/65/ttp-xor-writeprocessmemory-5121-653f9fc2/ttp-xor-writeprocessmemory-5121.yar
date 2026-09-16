rule TTP_XOR_WriteProcessMemory_5121 {
  strings:
    $key_5121 = { 06 53 [2] 34 71 [2] 32 44 [2] 1c 44 [2] 23 58 }

  condition:
    any of them
}