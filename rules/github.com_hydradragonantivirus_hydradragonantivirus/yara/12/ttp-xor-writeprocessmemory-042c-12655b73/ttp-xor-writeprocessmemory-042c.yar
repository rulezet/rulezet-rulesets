rule TTP_XOR_WriteProcessMemory_042c {
  strings:
    $key_042c = { 53 5e [2] 61 7c [2] 67 49 [2] 49 49 [2] 76 55 }

  condition:
    any of them
}