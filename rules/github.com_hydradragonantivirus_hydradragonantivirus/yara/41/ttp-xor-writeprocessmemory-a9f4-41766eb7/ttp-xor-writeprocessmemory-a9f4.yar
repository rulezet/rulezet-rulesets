rule TTP_XOR_WriteProcessMemory_a9f4 {
  strings:
    $key_a9f4 = { fe 86 [2] cc a4 [2] ca 91 [2] e4 91 [2] db 8d }

  condition:
    any of them
}