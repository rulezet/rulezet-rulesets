rule TTP_XOR_WriteProcessMemory_09ca {
  strings:
    $key_09ca = { 5e b8 [2] 6c 9a [2] 6a af [2] 44 af [2] 7b b3 }

  condition:
    any of them
}