rule TTP_XOR_WriteProcessMemory_9a01 {
  strings:
    $key_9a01 = { cd 73 [2] ff 51 [2] f9 64 [2] d7 64 [2] e8 78 }

  condition:
    any of them
}