rule TTP_XOR_WriteProcessMemory_6158 {
  strings:
    $key_6158 = { 36 2a [2] 04 08 [2] 02 3d [2] 2c 3d [2] 13 21 }

  condition:
    any of them
}