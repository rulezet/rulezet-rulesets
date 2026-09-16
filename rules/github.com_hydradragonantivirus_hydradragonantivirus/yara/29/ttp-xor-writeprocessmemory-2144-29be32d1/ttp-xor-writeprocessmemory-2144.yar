rule TTP_XOR_WriteProcessMemory_2144 {
  strings:
    $key_2144 = { 76 36 [2] 44 14 [2] 42 21 [2] 6c 21 [2] 53 3d }

  condition:
    any of them
}