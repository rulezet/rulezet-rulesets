rule TTP_XOR_WriteProcessMemory_3d38 {
  strings:
    $key_3d38 = { 6a 4a [2] 58 68 [2] 5e 5d [2] 70 5d [2] 4f 41 }

  condition:
    any of them
}