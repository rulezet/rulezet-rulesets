rule TTP_XOR_WriteProcessMemory_3f21 {
  strings:
    $key_3f21 = { 68 53 [2] 5a 71 [2] 5c 44 [2] 72 44 [2] 4d 58 }

  condition:
    any of them
}