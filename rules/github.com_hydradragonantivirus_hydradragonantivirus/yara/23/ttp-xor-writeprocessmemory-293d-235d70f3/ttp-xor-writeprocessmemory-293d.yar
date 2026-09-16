rule TTP_XOR_WriteProcessMemory_293d {
  strings:
    $key_293d = { 7e 4f [2] 4c 6d [2] 4a 58 [2] 64 58 [2] 5b 44 }

  condition:
    any of them
}