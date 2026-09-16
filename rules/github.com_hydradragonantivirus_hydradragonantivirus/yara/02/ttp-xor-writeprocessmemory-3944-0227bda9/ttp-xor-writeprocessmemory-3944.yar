rule TTP_XOR_WriteProcessMemory_3944 {
  strings:
    $key_3944 = { 6e 36 [2] 5c 14 [2] 5a 21 [2] 74 21 [2] 4b 3d }

  condition:
    any of them
}