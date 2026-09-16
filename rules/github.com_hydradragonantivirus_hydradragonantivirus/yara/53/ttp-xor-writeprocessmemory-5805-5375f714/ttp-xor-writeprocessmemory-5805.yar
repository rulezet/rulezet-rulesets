rule TTP_XOR_WriteProcessMemory_5805 {
  strings:
    $key_5805 = { 0f 77 [2] 3d 55 [2] 3b 60 [2] 15 60 [2] 2a 7c }

  condition:
    any of them
}