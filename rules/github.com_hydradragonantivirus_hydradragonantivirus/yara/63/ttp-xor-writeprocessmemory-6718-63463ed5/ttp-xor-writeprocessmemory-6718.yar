rule TTP_XOR_WriteProcessMemory_6718 {
  strings:
    $key_6718 = { 30 6a [2] 02 48 [2] 04 7d [2] 2a 7d [2] 15 61 }

  condition:
    any of them
}