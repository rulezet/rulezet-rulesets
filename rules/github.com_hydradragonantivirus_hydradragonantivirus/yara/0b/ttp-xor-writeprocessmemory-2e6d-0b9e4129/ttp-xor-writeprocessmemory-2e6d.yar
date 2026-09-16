rule TTP_XOR_WriteProcessMemory_2e6d {
  strings:
    $key_2e6d = { 79 1f [2] 4b 3d [2] 4d 08 [2] 63 08 [2] 5c 14 }

  condition:
    any of them
}