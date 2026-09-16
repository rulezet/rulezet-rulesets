rule TTP_XOR_WriteProcessMemory_7092 {
  strings:
    $key_7092 = { 27 e0 [2] 15 c2 [2] 13 f7 [2] 3d f7 [2] 02 eb }

  condition:
    any of them
}