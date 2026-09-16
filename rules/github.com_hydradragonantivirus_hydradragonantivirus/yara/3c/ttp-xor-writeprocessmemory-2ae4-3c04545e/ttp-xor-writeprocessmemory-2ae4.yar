rule TTP_XOR_WriteProcessMemory_2ae4 {
  strings:
    $key_2ae4 = { 7d 96 [2] 4f b4 [2] 49 81 [2] 67 81 [2] 58 9d }

  condition:
    any of them
}