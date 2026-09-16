rule TTP_XOR_WriteProcessMemory_1e34 {
  strings:
    $key_1e34 = { 49 46 [2] 7b 64 [2] 7d 51 [2] 53 51 [2] 6c 4d }

  condition:
    any of them
}