rule TTP_XOR_WriteProcessMemory_d8cc {
  strings:
    $key_d8cc = { 8f be [2] bd 9c [2] bb a9 [2] 95 a9 [2] aa b5 }

  condition:
    any of them
}