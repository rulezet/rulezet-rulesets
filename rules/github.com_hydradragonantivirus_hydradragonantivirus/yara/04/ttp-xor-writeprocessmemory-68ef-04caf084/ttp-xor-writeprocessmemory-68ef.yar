rule TTP_XOR_WriteProcessMemory_68ef {
  strings:
    $key_68ef = { 3f 9d [2] 0d bf [2] 0b 8a [2] 25 8a [2] 1a 96 }

  condition:
    any of them
}