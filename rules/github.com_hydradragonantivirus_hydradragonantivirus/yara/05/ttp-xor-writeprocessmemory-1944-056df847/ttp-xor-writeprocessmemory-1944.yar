rule TTP_XOR_WriteProcessMemory_1944 {
  strings:
    $key_1944 = { 4e 36 [2] 7c 14 [2] 7a 21 [2] 54 21 [2] 6b 3d }

  condition:
    any of them
}