rule TTP_XOR_WriteProcessMemory_202d {
  strings:
    $key_202d = { 77 5f [2] 45 7d [2] 43 48 [2] 6d 48 [2] 52 54 }

  condition:
    any of them
}