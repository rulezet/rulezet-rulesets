rule TTP_XOR_WriteProcessMemory_2eae {
  strings:
    $key_2eae = { 79 dc [2] 4b fe [2] 4d cb [2] 63 cb [2] 5c d7 }

  condition:
    any of them
}