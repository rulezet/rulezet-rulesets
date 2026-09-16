rule TTP_XOR_WriteProcessMemory_a903 {
  strings:
    $key_a903 = { fe 71 [2] cc 53 [2] ca 66 [2] e4 66 [2] db 7a }

  condition:
    any of them
}