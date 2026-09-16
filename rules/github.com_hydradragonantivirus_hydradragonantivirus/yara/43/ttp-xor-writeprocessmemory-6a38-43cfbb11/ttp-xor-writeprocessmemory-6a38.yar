rule TTP_XOR_WriteProcessMemory_6a38 {
  strings:
    $key_6a38 = { 3d 4a [2] 0f 68 [2] 09 5d [2] 27 5d [2] 18 41 }

  condition:
    any of them
}