rule TTP_XOR_WriteProcessMemory_022c {
  strings:
    $key_022c = { 55 5e [2] 67 7c [2] 61 49 [2] 4f 49 [2] 70 55 }

  condition:
    any of them
}