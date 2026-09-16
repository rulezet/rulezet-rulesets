rule TTP_XOR_WriteProcessMemory_6e36 {
  strings:
    $key_6e36 = { 39 44 [2] 0b 66 [2] 0d 53 [2] 23 53 [2] 1c 4f }

  condition:
    any of them
}