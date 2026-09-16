rule TTP_XOR_WriteProcessMemory_7028 {
  strings:
    $key_7028 = { 27 5a [2] 15 78 [2] 13 4d [2] 3d 4d [2] 02 51 }

  condition:
    any of them
}