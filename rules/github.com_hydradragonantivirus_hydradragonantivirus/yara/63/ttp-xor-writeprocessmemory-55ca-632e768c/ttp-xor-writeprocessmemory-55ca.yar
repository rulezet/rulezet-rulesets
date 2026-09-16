rule TTP_XOR_WriteProcessMemory_55ca {
  strings:
    $key_55ca = { 02 b8 [2] 30 9a [2] 36 af [2] 18 af [2] 27 b3 }

  condition:
    any of them
}