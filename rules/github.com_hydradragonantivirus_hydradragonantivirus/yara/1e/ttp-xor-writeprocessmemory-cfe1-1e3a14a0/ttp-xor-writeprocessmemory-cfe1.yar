rule TTP_XOR_WriteProcessMemory_cfe1 {
  strings:
    $key_cfe1 = { 98 93 [2] aa b1 [2] ac 84 [2] 82 84 [2] bd 98 }

  condition:
    any of them
}