rule TTP_XOR_WriteProcessMemory_023d {
  strings:
    $key_023d = { 55 4f [2] 67 6d [2] 61 58 [2] 4f 58 [2] 70 44 }

  condition:
    any of them
}