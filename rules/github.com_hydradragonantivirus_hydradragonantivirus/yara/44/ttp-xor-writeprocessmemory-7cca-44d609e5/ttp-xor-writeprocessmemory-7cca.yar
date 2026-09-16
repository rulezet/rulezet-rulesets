rule TTP_XOR_WriteProcessMemory_7cca {
  strings:
    $key_7cca = { 2b b8 [2] 19 9a [2] 1f af [2] 31 af [2] 0e b3 }

  condition:
    any of them
}