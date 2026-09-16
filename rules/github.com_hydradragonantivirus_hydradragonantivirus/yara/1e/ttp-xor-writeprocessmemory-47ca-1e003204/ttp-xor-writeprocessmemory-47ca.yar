rule TTP_XOR_WriteProcessMemory_47ca {
  strings:
    $key_47ca = { 10 b8 [2] 22 9a [2] 24 af [2] 0a af [2] 35 b3 }

  condition:
    any of them
}