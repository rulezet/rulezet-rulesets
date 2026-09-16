rule TTP_XOR_WriteProcessMemory_301d {
  strings:
    $key_301d = { 67 6f [2] 55 4d [2] 53 78 [2] 7d 78 [2] 42 64 }

  condition:
    any of them
}