rule TTP_XOR_WriteProcessMemory_7a34 {
  strings:
    $key_7a34 = { 2d 46 [2] 1f 64 [2] 19 51 [2] 37 51 [2] 08 4d }

  condition:
    any of them
}