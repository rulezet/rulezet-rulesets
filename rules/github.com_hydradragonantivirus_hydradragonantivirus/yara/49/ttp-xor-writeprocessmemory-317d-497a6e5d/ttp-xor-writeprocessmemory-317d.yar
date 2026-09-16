rule TTP_XOR_WriteProcessMemory_317d {
  strings:
    $key_317d = { 66 0f [2] 54 2d [2] 52 18 [2] 7c 18 [2] 43 04 }

  condition:
    any of them
}