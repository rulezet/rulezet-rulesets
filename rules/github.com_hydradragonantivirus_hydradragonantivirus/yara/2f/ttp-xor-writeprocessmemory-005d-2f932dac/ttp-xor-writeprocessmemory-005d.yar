rule TTP_XOR_WriteProcessMemory_005d {
  strings:
    $key_005d = { 57 2f [2] 65 0d [2] 63 38 [2] 4d 38 [2] 72 24 }

  condition:
    any of them
}