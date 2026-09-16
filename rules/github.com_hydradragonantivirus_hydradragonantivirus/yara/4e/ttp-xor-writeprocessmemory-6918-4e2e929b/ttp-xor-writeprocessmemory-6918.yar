rule TTP_XOR_WriteProcessMemory_6918 {
  strings:
    $key_6918 = { 3e 6a [2] 0c 48 [2] 0a 7d [2] 24 7d [2] 1b 61 }

  condition:
    any of them
}