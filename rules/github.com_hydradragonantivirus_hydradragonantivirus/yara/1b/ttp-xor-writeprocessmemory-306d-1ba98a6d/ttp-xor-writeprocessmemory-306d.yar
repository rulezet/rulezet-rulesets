rule TTP_XOR_WriteProcessMemory_306d {
  strings:
    $key_306d = { 67 1f [2] 55 3d [2] 53 08 [2] 7d 08 [2] 42 14 }

  condition:
    any of them
}