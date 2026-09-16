rule TTP_XOR_WriteProcessMemory_18ae {
  strings:
    $key_18ae = { 4f dc [2] 7d fe [2] 7b cb [2] 55 cb [2] 6a d7 }

  condition:
    any of them
}