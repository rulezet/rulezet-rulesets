rule TTP_XOR_WriteProcessMemory_1144 {
  strings:
    $key_1144 = { 46 36 [2] 74 14 [2] 72 21 [2] 5c 21 [2] 63 3d }

  condition:
    any of them
}