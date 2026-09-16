rule TTP_XOR_WriteProcessMemory_9af4 {
  strings:
    $key_9af4 = { cd 86 [2] ff a4 [2] f9 91 [2] d7 91 [2] e8 8d }

  condition:
    any of them
}