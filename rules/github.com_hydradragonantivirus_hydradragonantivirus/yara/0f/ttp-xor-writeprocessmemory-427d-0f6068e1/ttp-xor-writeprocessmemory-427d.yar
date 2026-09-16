rule TTP_XOR_WriteProcessMemory_427d {
  strings:
    $key_427d = { 15 0f [2] 27 2d [2] 21 18 [2] 0f 18 [2] 30 04 }

  condition:
    any of them
}