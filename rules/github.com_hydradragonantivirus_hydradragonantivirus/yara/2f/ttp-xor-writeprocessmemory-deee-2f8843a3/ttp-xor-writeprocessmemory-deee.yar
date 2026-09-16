rule TTP_XOR_WriteProcessMemory_deee {
  strings:
    $key_deee = { 89 9c [2] bb be [2] bd 8b [2] 93 8b [2] ac 97 }

  condition:
    any of them
}