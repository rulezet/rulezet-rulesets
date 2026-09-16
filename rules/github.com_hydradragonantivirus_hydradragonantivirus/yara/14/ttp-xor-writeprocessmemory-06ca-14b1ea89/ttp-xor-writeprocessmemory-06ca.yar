rule TTP_XOR_WriteProcessMemory_06ca {
  strings:
    $key_06ca = { 51 b8 [2] 63 9a [2] 65 af [2] 4b af [2] 74 b3 }

  condition:
    any of them
}