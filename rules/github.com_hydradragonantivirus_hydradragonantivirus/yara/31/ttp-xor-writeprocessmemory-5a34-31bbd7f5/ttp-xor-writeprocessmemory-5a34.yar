rule TTP_XOR_WriteProcessMemory_5a34 {
  strings:
    $key_5a34 = { 0d 46 [2] 3f 64 [2] 39 51 [2] 17 51 [2] 28 4d }

  condition:
    any of them
}