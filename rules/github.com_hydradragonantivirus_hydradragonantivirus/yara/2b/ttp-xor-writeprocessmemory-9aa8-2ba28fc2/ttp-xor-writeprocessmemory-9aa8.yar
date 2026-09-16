rule TTP_XOR_WriteProcessMemory_9aa8 {
  strings:
    $key_9aa8 = { cd da [2] ff f8 [2] f9 cd [2] d7 cd [2] e8 d1 }

  condition:
    any of them
}