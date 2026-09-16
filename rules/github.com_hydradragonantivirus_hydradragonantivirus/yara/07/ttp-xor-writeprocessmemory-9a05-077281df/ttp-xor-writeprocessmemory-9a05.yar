rule TTP_XOR_WriteProcessMemory_9a05 {
  strings:
    $key_9a05 = { cd 77 [2] ff 55 [2] f9 60 [2] d7 60 [2] e8 7c }

  condition:
    any of them
}