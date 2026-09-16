rule TTP_XOR_WriteProcessMemory_3d18 {
  strings:
    $key_3d18 = { 6a 6a [2] 58 48 [2] 5e 7d [2] 70 7d [2] 4f 61 }

  condition:
    any of them
}