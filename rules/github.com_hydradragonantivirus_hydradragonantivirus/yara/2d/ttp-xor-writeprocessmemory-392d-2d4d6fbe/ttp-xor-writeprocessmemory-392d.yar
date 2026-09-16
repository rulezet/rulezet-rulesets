rule TTP_XOR_WriteProcessMemory_392d {
  strings:
    $key_392d = { 6e 5f [2] 5c 7d [2] 5a 48 [2] 74 48 [2] 4b 54 }

  condition:
    any of them
}