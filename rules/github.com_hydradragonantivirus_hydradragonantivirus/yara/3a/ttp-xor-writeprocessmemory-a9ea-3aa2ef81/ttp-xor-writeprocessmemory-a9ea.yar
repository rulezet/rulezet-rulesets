rule TTP_XOR_WriteProcessMemory_a9ea {
  strings:
    $key_a9ea = { fe 98 [2] cc ba [2] ca 8f [2] e4 8f [2] db 93 }

  condition:
    any of them
}