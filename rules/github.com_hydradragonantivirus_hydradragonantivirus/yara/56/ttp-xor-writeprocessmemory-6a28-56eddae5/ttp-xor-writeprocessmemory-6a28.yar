rule TTP_XOR_WriteProcessMemory_6a28 {
  strings:
    $key_6a28 = { 3d 5a [2] 0f 78 [2] 09 4d [2] 27 4d [2] 18 51 }

  condition:
    any of them
}