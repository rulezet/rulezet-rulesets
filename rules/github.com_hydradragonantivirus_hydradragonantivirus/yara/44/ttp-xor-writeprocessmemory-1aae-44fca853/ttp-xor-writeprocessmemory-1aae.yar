rule TTP_XOR_WriteProcessMemory_1aae {
  strings:
    $key_1aae = { 4d dc [2] 7f fe [2] 79 cb [2] 57 cb [2] 68 d7 }

  condition:
    any of them
}