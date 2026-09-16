rule TTP_XOR_WriteProcessMemory_3eae {
  strings:
    $key_3eae = { 69 dc [2] 5b fe [2] 5d cb [2] 73 cb [2] 4c d7 }

  condition:
    any of them
}