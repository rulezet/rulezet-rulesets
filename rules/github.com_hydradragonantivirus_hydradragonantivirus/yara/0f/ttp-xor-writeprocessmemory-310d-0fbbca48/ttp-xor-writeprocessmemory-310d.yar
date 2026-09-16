rule TTP_XOR_WriteProcessMemory_310d {
  strings:
    $key_310d = { 66 7f [2] 54 5d [2] 52 68 [2] 7c 68 [2] 43 74 }

  condition:
    any of them
}