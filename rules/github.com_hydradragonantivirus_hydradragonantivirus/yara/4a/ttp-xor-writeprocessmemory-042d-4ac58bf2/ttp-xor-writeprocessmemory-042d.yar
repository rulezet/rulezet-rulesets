rule TTP_XOR_WriteProcessMemory_042d {
  strings:
    $key_042d = { 53 5f [2] 61 7d [2] 67 48 [2] 49 48 [2] 76 54 }

  condition:
    any of them
}