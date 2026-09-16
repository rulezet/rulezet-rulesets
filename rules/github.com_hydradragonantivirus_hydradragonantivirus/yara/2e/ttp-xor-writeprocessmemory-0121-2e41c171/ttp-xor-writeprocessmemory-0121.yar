rule TTP_XOR_WriteProcessMemory_0121 {
  strings:
    $key_0121 = { 56 53 [2] 64 71 [2] 62 44 [2] 4c 44 [2] 73 58 }

  condition:
    any of them
}