rule TTP_XOR_WriteProcessMemory_290c {
  strings:
    $key_290c = { 7e 7e [2] 4c 5c [2] 4a 69 [2] 64 69 [2] 5b 75 }

  condition:
    any of them
}