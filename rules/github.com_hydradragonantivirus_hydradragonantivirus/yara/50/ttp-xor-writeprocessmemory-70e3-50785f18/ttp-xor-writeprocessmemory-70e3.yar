rule TTP_XOR_WriteProcessMemory_70e3 {
  strings:
    $key_70e3 = { 27 91 [2] 15 b3 [2] 13 86 [2] 3d 86 [2] 02 9a }

  condition:
    any of them
}