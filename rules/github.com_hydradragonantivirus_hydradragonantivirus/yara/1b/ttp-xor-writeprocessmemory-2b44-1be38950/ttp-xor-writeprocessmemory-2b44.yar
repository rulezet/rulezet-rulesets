rule TTP_XOR_WriteProcessMemory_2b44 {
  strings:
    $key_2b44 = { 7c 36 [2] 4e 14 [2] 48 21 [2] 66 21 [2] 59 3d }

  condition:
    any of them
}