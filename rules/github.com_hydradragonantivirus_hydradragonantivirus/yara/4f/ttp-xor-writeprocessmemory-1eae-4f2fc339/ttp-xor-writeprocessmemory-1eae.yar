rule TTP_XOR_WriteProcessMemory_1eae {
  strings:
    $key_1eae = { 49 dc [2] 7b fe [2] 7d cb [2] 53 cb [2] 6c d7 }

  condition:
    any of them
}