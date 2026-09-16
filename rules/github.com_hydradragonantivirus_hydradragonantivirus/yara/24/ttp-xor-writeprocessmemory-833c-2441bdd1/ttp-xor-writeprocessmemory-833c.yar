rule TTP_XOR_WriteProcessMemory_833c {
  strings:
    $key_833c = { d4 4e [2] e6 6c [2] e0 59 [2] ce 59 [2] f1 45 }

  condition:
    any of them
}