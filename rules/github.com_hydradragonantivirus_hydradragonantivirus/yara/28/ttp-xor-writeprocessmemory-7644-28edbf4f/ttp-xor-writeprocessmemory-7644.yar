rule TTP_XOR_WriteProcessMemory_7644 {
  strings:
    $key_7644 = { 21 36 [2] 13 14 [2] 15 21 [2] 3b 21 [2] 04 3d }

  condition:
    any of them
}