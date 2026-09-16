rule TTP_XOR_WriteProcessMemory_d8cd {
  strings:
    $key_d8cd = { 8f bf [2] bd 9d [2] bb a8 [2] 95 a8 [2] aa b4 }

  condition:
    any of them
}