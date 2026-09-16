rule TTP_XOR_WriteProcessMemory_dee9 {
  strings:
    $key_dee9 = { 89 9b [2] bb b9 [2] bd 8c [2] 93 8c [2] ac 90 }

  condition:
    any of them
}