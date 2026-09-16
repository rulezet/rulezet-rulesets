rule TTP_XOR_WriteProcessMemory_2ae3 {
  strings:
    $key_2ae3 = { 7d 91 [2] 4f b3 [2] 49 86 [2] 67 86 [2] 58 9a }

  condition:
    any of them
}