rule TTP_XOR_WriteProcessMemory_7158 {
  strings:
    $key_7158 = { 26 2a [2] 14 08 [2] 12 3d [2] 3c 3d [2] 03 21 }

  condition:
    any of them
}