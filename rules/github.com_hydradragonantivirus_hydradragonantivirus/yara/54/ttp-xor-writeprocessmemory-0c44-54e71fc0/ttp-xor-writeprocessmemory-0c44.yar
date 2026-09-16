rule TTP_XOR_WriteProcessMemory_0c44 {
  strings:
    $key_0c44 = { 5b 36 [2] 69 14 [2] 6f 21 [2] 41 21 [2] 7e 3d }

  condition:
    any of them
}