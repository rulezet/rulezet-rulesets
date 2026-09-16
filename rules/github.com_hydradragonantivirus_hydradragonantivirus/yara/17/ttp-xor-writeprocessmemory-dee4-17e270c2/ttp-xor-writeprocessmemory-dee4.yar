rule TTP_XOR_WriteProcessMemory_dee4 {
  strings:
    $key_dee4 = { 89 96 [2] bb b4 [2] bd 81 [2] 93 81 [2] ac 9d }

  condition:
    any of them
}