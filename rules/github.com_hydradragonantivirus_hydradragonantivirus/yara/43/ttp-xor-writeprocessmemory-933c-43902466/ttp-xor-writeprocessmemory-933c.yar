rule TTP_XOR_WriteProcessMemory_933c {
  strings:
    $key_933c = { c4 4e [2] f6 6c [2] f0 59 [2] de 59 [2] e1 45 }

  condition:
    any of them
}