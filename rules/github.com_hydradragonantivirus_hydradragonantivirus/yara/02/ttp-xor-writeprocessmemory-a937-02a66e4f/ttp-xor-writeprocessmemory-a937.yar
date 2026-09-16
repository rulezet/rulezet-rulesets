rule TTP_XOR_WriteProcessMemory_a937 {
  strings:
    $key_a937 = { fe 45 [2] cc 67 [2] ca 52 [2] e4 52 [2] db 4e }

  condition:
    any of them
}