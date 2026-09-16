rule TTP_XOR_WriteProcessMemory_377d {
  strings:
    $key_377d = { 60 0f [2] 52 2d [2] 54 18 [2] 7a 18 [2] 45 04 }

  condition:
    any of them
}