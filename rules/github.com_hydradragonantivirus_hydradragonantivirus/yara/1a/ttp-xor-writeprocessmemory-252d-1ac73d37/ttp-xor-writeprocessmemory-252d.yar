rule TTP_XOR_WriteProcessMemory_252d {
  strings:
    $key_252d = { 72 5f [2] 40 7d [2] 46 48 [2] 68 48 [2] 57 54 }

  condition:
    any of them
}