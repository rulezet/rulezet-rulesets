rule TTP_XOR_WriteProcessMemory_38ae {
  strings:
    $key_38ae = { 6f dc [2] 5d fe [2] 5b cb [2] 75 cb [2] 4a d7 }

  condition:
    any of them
}