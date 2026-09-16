rule TTP_XOR_WriteProcessMemory_024c {
  strings:
    $key_024c = { 55 3e [2] 67 1c [2] 61 29 [2] 4f 29 [2] 70 35 }

  condition:
    any of them
}