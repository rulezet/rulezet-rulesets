rule TTP_XOR_WriteProcessMemory_640d {
  strings:
    $key_640d = { 33 7f [2] 01 5d [2] 07 68 [2] 29 68 [2] 16 74 }

  condition:
    any of them
}