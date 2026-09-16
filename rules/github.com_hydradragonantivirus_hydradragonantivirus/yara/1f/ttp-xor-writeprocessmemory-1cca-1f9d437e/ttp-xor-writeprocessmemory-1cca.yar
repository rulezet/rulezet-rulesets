rule TTP_XOR_WriteProcessMemory_1cca {
  strings:
    $key_1cca = { 4b b8 [2] 79 9a [2] 7f af [2] 51 af [2] 6e b3 }

  condition:
    any of them
}