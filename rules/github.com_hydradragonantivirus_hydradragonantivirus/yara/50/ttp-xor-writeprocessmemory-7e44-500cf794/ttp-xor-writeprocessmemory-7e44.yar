rule TTP_XOR_WriteProcessMemory_7e44 {
  strings:
    $key_7e44 = { 29 36 [2] 1b 14 [2] 1d 21 [2] 33 21 [2] 0c 3d }

  condition:
    any of them
}