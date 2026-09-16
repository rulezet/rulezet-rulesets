rule TTP_XOR_WriteProcessMemory_3b6d {
  strings:
    $key_3b6d = { 6c 1f [2] 5e 3d [2] 58 08 [2] 76 08 [2] 49 14 }

  condition:
    any of them
}