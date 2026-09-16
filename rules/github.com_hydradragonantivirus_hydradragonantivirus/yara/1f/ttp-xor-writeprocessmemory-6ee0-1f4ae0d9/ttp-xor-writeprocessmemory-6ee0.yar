rule TTP_XOR_WriteProcessMemory_6ee0 {
  strings:
    $key_6ee0 = { 39 92 [2] 0b b0 [2] 0d 85 [2] 23 85 [2] 1c 99 }

  condition:
    any of them
}