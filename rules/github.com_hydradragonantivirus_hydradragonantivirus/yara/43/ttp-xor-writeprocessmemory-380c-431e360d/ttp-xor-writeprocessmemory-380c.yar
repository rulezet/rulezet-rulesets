rule TTP_XOR_WriteProcessMemory_380c {
  strings:
    $key_380c = { 6f 7e [2] 5d 5c [2] 5b 69 [2] 75 69 [2] 4a 75 }

  condition:
    any of them
}