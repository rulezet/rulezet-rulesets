rule TTP_XOR_WriteProcessMemory_19ae {
  strings:
    $key_19ae = { 4e dc [2] 7c fe [2] 7a cb [2] 54 cb [2] 6b d7 }

  condition:
    any of them
}