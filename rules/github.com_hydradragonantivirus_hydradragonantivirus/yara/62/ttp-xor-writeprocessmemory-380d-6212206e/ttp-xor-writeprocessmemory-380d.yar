rule TTP_XOR_WriteProcessMemory_380d {
  strings:
    $key_380d = { 6f 7f [2] 5d 5d [2] 5b 68 [2] 75 68 [2] 4a 74 }

  condition:
    any of them
}