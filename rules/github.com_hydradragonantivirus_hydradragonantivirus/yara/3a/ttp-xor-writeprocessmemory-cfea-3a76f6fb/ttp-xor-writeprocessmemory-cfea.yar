rule TTP_XOR_WriteProcessMemory_cfea {
  strings:
    $key_cfea = { 98 98 [2] aa ba [2] ac 8f [2] 82 8f [2] bd 93 }

  condition:
    any of them
}