rule TTP_XOR_WriteProcessMemory_021b {
  strings:
    $key_021b = { 55 69 [2] 67 4b [2] 61 7e [2] 4f 7e [2] 70 62 }

  condition:
    any of them
}