rule TTP_XOR_WriteProcessMemory_1bae {
  strings:
    $key_1bae = { 4c dc [2] 7e fe [2] 78 cb [2] 56 cb [2] 69 d7 }

  condition:
    any of them
}