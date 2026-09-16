rule TTP_XOR_WriteProcessMemory_27ca {
  strings:
    $key_27ca = { 70 b8 [2] 42 9a [2] 44 af [2] 6a af [2] 55 b3 }

  condition:
    any of them
}