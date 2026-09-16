rule TTP_XOR_WriteProcessMemory_689c {
  strings:
    $key_689c = { 3f ee [2] 0d cc [2] 0b f9 [2] 25 f9 [2] 1a e5 }

  condition:
    any of them
}