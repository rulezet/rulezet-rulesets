rule TTP_XOR_WriteProcessMemory_6814 {
  strings:
    $key_6814 = { 3f 66 [2] 0d 44 [2] 0b 71 [2] 25 71 [2] 1a 6d }

  condition:
    any of them
}