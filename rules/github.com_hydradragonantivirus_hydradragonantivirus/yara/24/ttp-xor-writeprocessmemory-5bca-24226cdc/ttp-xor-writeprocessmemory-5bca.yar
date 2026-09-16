rule TTP_XOR_WriteProcessMemory_5bca {
  strings:
    $key_5bca = { 0c b8 [2] 3e 9a [2] 38 af [2] 16 af [2] 29 b3 }

  condition:
    any of them
}