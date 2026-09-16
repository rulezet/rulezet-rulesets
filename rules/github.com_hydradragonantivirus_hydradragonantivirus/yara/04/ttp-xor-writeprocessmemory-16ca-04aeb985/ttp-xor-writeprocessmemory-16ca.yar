rule TTP_XOR_WriteProcessMemory_16ca {
  strings:
    $key_16ca = { 41 b8 [2] 73 9a [2] 75 af [2] 5b af [2] 64 b3 }

  condition:
    any of them
}