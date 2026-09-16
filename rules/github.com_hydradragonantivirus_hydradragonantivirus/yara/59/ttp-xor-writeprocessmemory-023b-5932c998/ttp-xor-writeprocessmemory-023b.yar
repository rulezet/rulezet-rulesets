rule TTP_XOR_WriteProcessMemory_023b {
  strings:
    $key_023b = { 55 49 [2] 67 6b [2] 61 5e [2] 4f 5e [2] 70 42 }

  condition:
    any of them
}