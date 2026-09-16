rule TTP_XOR_WriteProcessMemory_3bca {
  strings:
    $key_3bca = { 6c b8 [2] 5e 9a [2] 58 af [2] 76 af [2] 49 b3 }

  condition:
    any of them
}