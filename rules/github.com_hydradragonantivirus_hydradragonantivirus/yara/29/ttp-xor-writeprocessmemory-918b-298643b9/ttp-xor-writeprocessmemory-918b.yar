rule TTP_XOR_WriteProcessMemory_918b {
  strings:
    $key_918b = { c6 f9 [2] f4 db [2] f2 ee [2] dc ee [2] e3 f2 }

  condition:
    any of them
}