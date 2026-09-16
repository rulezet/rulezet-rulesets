rule TTP_XOR_WriteProcessMemory_369b {
  strings:
    $key_369b = { 61 e9 [2] 53 cb [2] 55 fe [2] 7b fe [2] 44 e2 }

  condition:
    any of them
}