rule TTP_XOR_WriteProcessMemory_253c {
  strings:
    $key_253c = { 72 4e [2] 40 6c [2] 46 59 [2] 68 59 [2] 57 45 }

  condition:
    any of them
}