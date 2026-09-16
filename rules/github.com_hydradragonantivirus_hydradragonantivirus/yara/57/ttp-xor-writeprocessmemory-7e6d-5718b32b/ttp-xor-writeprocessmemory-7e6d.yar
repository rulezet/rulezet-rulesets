rule TTP_XOR_WriteProcessMemory_7e6d {
  strings:
    $key_7e6d = { 29 1f [2] 1b 3d [2] 1d 08 [2] 33 08 [2] 0c 14 }

  condition:
    any of them
}