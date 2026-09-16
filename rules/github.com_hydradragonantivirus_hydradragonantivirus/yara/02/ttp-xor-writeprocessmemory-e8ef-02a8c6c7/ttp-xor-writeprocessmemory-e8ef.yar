rule TTP_XOR_WriteProcessMemory_e8ef {
  strings:
    $key_e8ef = { bf 9d [2] 8d bf [2] 8b 8a [2] a5 8a [2] 9a 96 }

  condition:
    any of them
}