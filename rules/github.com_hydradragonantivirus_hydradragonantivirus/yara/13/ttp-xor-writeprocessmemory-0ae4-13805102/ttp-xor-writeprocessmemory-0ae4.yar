rule TTP_XOR_WriteProcessMemory_0ae4 {
  strings:
    $key_0ae4 = { 5d 96 [2] 6f b4 [2] 69 81 [2] 47 81 [2] 78 9d }

  condition:
    any of them
}