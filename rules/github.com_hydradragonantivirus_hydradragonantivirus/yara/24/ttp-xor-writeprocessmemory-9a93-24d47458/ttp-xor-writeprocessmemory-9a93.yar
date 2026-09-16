rule TTP_XOR_WriteProcessMemory_9a93 {
  strings:
    $key_9a93 = { cd e1 [2] ff c3 [2] f9 f6 [2] d7 f6 [2] e8 ea }

  condition:
    any of them
}