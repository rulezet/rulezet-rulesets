rule TTP_XOR_WriteProcessMemory_168b {
  strings:
    $key_168b = { 41 f9 [2] 73 db [2] 75 ee [2] 5b ee [2] 64 f2 }

  condition:
    any of them
}