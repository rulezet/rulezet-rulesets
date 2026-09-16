rule TTP_XOR_WriteProcessMemory_0e6d {
  strings:
    $key_0e6d = { 59 1f [2] 6b 3d [2] 6d 08 [2] 43 08 [2] 7c 14 }

  condition:
    any of them
}