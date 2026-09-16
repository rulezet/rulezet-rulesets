rule TTP_XOR_WriteProcessMemory_59ca {
  strings:
    $key_59ca = { 0e b8 [2] 3c 9a [2] 3a af [2] 14 af [2] 2b b3 }

  condition:
    any of them
}