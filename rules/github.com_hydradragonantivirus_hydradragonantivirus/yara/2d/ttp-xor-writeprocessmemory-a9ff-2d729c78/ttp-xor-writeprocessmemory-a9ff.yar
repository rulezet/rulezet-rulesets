rule TTP_XOR_WriteProcessMemory_a9ff {
  strings:
    $key_a9ff = { fe 8d [2] cc af [2] ca 9a [2] e4 9a [2] db 86 }

  condition:
    any of them
}