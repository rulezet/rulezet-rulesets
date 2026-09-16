rule TTP_XOR_WriteProcessMemory_3d79 {
  strings:
    $key_3d79 = { 6a 0b [2] 58 29 [2] 5e 1c [2] 70 1c [2] 4f 00 }

  condition:
    any of them
}