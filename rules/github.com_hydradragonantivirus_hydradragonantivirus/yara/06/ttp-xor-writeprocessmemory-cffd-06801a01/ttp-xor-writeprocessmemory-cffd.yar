rule TTP_XOR_WriteProcessMemory_cffd {
  strings:
    $key_cffd = { 98 8f [2] aa ad [2] ac 98 [2] 82 98 [2] bd 84 }

  condition:
    any of them
}