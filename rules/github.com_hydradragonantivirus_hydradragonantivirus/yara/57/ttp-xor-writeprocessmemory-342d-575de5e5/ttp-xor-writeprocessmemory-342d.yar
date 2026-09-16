rule TTP_XOR_WriteProcessMemory_342d {
  strings:
    $key_342d = { 63 5f [2] 51 7d [2] 57 48 [2] 79 48 [2] 46 54 }

  condition:
    any of them
}