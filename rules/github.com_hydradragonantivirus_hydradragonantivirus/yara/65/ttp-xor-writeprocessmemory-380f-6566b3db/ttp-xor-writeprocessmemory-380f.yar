rule TTP_XOR_WriteProcessMemory_380f {
  strings:
    $key_380f = { 6f 7d [2] 5d 5f [2] 5b 6a [2] 75 6a [2] 4a 76 }

  condition:
    any of them
}