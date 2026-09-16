rule TTP_XOR_WriteProcessMemory_3873 {
  strings:
    $key_3873 = { 6f 01 [2] 5d 23 [2] 5b 16 [2] 75 16 [2] 4a 0a }

  condition:
    any of them
}