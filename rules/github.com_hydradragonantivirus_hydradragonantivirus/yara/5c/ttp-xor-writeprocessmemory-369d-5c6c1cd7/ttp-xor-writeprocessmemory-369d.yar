rule TTP_XOR_WriteProcessMemory_369d {
  strings:
    $key_369d = { 61 ef [2] 53 cd [2] 55 f8 [2] 7b f8 [2] 44 e4 }

  condition:
    any of them
}