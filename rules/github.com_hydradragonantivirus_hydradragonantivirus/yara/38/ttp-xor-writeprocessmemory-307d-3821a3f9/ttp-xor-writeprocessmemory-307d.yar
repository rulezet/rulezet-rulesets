rule TTP_XOR_WriteProcessMemory_307d {
  strings:
    $key_307d = { 67 0f [2] 55 2d [2] 53 18 [2] 7d 18 [2] 42 04 }

  condition:
    any of them
}