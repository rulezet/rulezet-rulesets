rule TTP_XOR_WriteProcessMemory_312d {
  strings:
    $key_312d = { 66 5f [2] 54 7d [2] 52 48 [2] 7c 48 [2] 43 54 }

  condition:
    any of them
}