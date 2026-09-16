rule TTP_XOR_WriteProcessMemory_dee3 {
  strings:
    $key_dee3 = { 89 91 [2] bb b3 [2] bd 86 [2] 93 86 [2] ac 9a }

  condition:
    any of them
}