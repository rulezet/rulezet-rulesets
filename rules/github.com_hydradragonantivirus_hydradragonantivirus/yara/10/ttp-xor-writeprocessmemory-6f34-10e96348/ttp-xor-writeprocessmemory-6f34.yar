rule TTP_XOR_WriteProcessMemory_6f34 {
  strings:
    $key_6f34 = { 38 46 [2] 0a 64 [2] 0c 51 [2] 22 51 [2] 1d 4d }

  condition:
    any of them
}