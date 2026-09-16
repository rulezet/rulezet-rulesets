rule TTP_XOR_WriteProcessMemory_18ef {
  strings:
    $key_18ef = { 4f 9d [2] 7d bf [2] 7b 8a [2] 55 8a [2] 6a 96 }

  condition:
    any of them
}