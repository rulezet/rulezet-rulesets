rule TTP_XOR_WriteProcessMemory_cfe3 {
  strings:
    $key_cfe3 = { 98 91 [2] aa b3 [2] ac 86 [2] 82 86 [2] bd 9a }

  condition:
    any of them
}