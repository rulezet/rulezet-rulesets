rule TTP_XOR_WriteProcessMemory_262c {
  strings:
    $key_262c = { 71 5e [2] 43 7c [2] 45 49 [2] 6b 49 [2] 54 55 }

  condition:
    any of them
}