rule TTP_XOR_WriteProcessMemory_7844 {
  strings:
    $key_7844 = { 2f 36 [2] 1d 14 [2] 1b 21 [2] 35 21 [2] 0a 3d }

  condition:
    any of them
}