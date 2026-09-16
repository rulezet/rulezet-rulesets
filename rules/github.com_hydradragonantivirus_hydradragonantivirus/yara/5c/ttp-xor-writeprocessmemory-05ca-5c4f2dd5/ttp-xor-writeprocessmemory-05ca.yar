rule TTP_XOR_WriteProcessMemory_05ca {
  strings:
    $key_05ca = { 52 b8 [2] 60 9a [2] 66 af [2] 48 af [2] 77 b3 }

  condition:
    any of them
}