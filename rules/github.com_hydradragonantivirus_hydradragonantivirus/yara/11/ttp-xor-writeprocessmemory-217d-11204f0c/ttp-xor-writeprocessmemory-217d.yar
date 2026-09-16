rule TTP_XOR_WriteProcessMemory_217d {
  strings:
    $key_217d = { 76 0f [2] 44 2d [2] 42 18 [2] 6c 18 [2] 53 04 }

  condition:
    any of them
}