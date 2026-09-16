rule TTP_XOR_WriteProcessMemory_eebd {
  strings:
    $key_eebd = { b9 cf [2] 8b ed [2] 8d d8 [2] a3 d8 [2] 9c c4 }

  condition:
    any of them
}