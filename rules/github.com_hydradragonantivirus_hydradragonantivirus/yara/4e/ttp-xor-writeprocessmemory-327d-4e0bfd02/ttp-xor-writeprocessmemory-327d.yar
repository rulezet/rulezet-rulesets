rule TTP_XOR_WriteProcessMemory_327d {
  strings:
    $key_327d = { 65 0f [2] 57 2d [2] 51 18 [2] 7f 18 [2] 40 04 }

  condition:
    any of them
}