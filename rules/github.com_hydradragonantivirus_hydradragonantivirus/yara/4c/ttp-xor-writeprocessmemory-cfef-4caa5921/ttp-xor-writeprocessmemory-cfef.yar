rule TTP_XOR_WriteProcessMemory_cfef {
  strings:
    $key_cfef = { 98 9d [2] aa bf [2] ac 8a [2] 82 8a [2] bd 96 }

  condition:
    any of them
}