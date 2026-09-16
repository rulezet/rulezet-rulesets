rule TTP_XOR_WriteProcessMemory_a9fd {
  strings:
    $key_a9fd = { fe 8f [2] cc ad [2] ca 98 [2] e4 98 [2] db 84 }

  condition:
    any of them
}