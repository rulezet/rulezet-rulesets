rule TTP_XOR_WriteProcessMemory_4bae {
  strings:
    $key_4bae = { 1c dc [2] 2e fe [2] 28 cb [2] 06 cb [2] 39 d7 }

  condition:
    any of them
}