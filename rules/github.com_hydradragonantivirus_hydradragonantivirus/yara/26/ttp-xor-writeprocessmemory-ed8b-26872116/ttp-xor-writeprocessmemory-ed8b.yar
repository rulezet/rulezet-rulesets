rule TTP_XOR_WriteProcessMemory_ed8b {
  strings:
    $key_ed8b = { ba f9 [2] 88 db [2] 8e ee [2] a0 ee [2] 9f f2 }

  condition:
    any of them
}