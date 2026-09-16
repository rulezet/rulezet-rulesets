rule TTP_XOR_WriteProcessMemory_2fe4 {
  strings:
    $key_2fe4 = { 78 96 [2] 4a b4 [2] 4c 81 [2] 62 81 [2] 5d 9d }

  condition:
    any of them
}