rule TTP_XOR_WriteProcessMemory_f98b {
  strings:
    $key_f98b = { ae f9 [2] 9c db [2] 9a ee [2] b4 ee [2] 8b f2 }

  condition:
    any of them
}