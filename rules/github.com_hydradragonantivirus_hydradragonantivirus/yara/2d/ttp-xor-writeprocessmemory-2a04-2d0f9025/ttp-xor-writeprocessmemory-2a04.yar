rule TTP_XOR_WriteProcessMemory_2a04 {
  strings:
    $key_2a04 = { 7d 76 [2] 4f 54 [2] 49 61 [2] 67 61 [2] 58 7d }

  condition:
    any of them
}