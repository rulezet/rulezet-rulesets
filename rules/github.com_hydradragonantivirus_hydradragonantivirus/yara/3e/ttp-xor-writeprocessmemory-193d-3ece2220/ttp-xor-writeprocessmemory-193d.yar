rule TTP_XOR_WriteProcessMemory_193d {
  strings:
    $key_193d = { 4e 4f [2] 7c 6d [2] 7a 58 [2] 54 58 [2] 6b 44 }

  condition:
    any of them
}