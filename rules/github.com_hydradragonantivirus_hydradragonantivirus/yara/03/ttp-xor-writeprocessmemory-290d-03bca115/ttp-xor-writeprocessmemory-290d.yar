rule TTP_XOR_WriteProcessMemory_290d {
  strings:
    $key_290d = { 7e 7f [2] 4c 5d [2] 4a 68 [2] 64 68 [2] 5b 74 }

  condition:
    any of them
}