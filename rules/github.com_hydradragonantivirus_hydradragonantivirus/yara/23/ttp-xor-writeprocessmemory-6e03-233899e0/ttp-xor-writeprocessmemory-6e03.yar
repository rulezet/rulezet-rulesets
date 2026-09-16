rule TTP_XOR_WriteProcessMemory_6e03 {
  strings:
    $key_6e03 = { 39 71 [2] 0b 53 [2] 0d 66 [2] 23 66 [2] 1c 7a }

  condition:
    any of them
}