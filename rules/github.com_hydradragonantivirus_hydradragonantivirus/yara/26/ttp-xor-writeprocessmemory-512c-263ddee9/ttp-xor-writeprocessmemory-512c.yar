rule TTP_XOR_WriteProcessMemory_512c {
  strings:
    $key_512c = { 06 5e [2] 34 7c [2] 32 49 [2] 1c 49 [2] 23 55 }

  condition:
    any of them
}