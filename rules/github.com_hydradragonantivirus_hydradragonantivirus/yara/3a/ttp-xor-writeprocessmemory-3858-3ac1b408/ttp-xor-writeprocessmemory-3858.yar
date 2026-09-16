rule TTP_XOR_WriteProcessMemory_3858 {
  strings:
    $key_3858 = { 6f 2a [2] 5d 08 [2] 5b 3d [2] 75 3d [2] 4a 21 }

  condition:
    any of them
}