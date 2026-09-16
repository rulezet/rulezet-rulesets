rule TTP_XOR_WriteProcessMemory_007d {
  strings:
    $key_007d = { 57 0f [2] 65 2d [2] 63 18 [2] 4d 18 [2] 72 04 }

  condition:
    any of them
}