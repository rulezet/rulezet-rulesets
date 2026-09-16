rule TTP_XOR_WriteProcessMemory_3058 {
  strings:
    $key_3058 = { 67 2a [2] 55 08 [2] 53 3d [2] 7d 3d [2] 42 21 }

  condition:
    any of them
}