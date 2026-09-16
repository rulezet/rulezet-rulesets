rule TTP_XOR_WriteProcessMemory_0cca {
  strings:
    $key_0cca = { 5b b8 [2] 69 9a [2] 6f af [2] 41 af [2] 7e b3 }

  condition:
    any of them
}