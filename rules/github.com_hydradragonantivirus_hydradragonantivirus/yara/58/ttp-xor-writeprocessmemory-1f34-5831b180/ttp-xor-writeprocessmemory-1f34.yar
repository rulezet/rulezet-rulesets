rule TTP_XOR_WriteProcessMemory_1f34 {
  strings:
    $key_1f34 = { 48 46 [2] 7a 64 [2] 7c 51 [2] 52 51 [2] 6d 4d }

  condition:
    any of them
}