rule TTP_XOR_WriteProcessMemory_19ca {
  strings:
    $key_19ca = { 4e b8 [2] 7c 9a [2] 7a af [2] 54 af [2] 6b b3 }

  condition:
    any of them
}