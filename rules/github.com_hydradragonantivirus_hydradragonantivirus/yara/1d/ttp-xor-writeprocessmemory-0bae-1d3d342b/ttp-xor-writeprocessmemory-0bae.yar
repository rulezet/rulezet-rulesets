rule TTP_XOR_WriteProcessMemory_0bae {
  strings:
    $key_0bae = { 5c dc [2] 6e fe [2] 68 cb [2] 46 cb [2] 79 d7 }

  condition:
    any of them
}