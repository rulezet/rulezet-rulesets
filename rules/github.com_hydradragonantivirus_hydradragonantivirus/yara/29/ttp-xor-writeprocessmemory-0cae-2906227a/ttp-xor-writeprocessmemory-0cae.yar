rule TTP_XOR_WriteProcessMemory_0cae {
  strings:
    $key_0cae = { 5b dc [2] 69 fe [2] 6f cb [2] 41 cb [2] 7e d7 }

  condition:
    any of them
}