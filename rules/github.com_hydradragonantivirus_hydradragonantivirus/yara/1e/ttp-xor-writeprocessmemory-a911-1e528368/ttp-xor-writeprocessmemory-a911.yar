rule TTP_XOR_WriteProcessMemory_a911 {
  strings:
    $key_a911 = { fe 63 [2] cc 41 [2] ca 74 [2] e4 74 [2] db 68 }

  condition:
    any of them
}