rule TTP_XOR_WriteProcessMemory_131b {
  strings:
    $key_131b = { 44 69 [2] 76 4b [2] 70 7e [2] 5e 7e [2] 61 62 }

  condition:
    any of them
}