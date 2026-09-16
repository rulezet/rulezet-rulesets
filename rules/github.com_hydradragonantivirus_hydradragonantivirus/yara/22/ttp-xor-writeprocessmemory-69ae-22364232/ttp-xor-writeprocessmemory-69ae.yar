rule TTP_XOR_WriteProcessMemory_69ae {
  strings:
    $key_69ae = { 3e dc [2] 0c fe [2] 0a cb [2] 24 cb [2] 1b d7 }

  condition:
    any of them
}