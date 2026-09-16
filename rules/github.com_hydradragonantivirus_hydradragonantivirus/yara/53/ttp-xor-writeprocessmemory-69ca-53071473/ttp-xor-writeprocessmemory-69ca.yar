rule TTP_XOR_WriteProcessMemory_69ca {
  strings:
    $key_69ca = { 3e b8 [2] 0c 9a [2] 0a af [2] 24 af [2] 1b b3 }

  condition:
    any of them
}