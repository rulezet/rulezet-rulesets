rule TTP_XOR_WriteProcessMemory_39ae {
  strings:
    $key_39ae = { 6e dc [2] 5c fe [2] 5a cb [2] 74 cb [2] 4b d7 }

  condition:
    any of them
}