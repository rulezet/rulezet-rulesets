rule TTP_XOR_WriteProcessMemory_6971 {
  strings:
    $key_6971 = { 3e 03 [2] 0c 21 [2] 0a 14 [2] 24 14 [2] 1b 08 }

  condition:
    any of them
}