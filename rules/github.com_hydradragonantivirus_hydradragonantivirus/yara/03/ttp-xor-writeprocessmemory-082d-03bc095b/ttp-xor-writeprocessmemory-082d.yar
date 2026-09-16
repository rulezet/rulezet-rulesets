rule TTP_XOR_WriteProcessMemory_082d {
  strings:
    $key_082d = { 5f 5f [2] 6d 7d [2] 6b 48 [2] 45 48 [2] 7a 54 }

  condition:
    any of them
}