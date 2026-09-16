rule TTP_XOR_WriteProcessMemory_467d {
  strings:
    $key_467d = { 11 0f [2] 23 2d [2] 25 18 [2] 0b 18 [2] 34 04 }

  condition:
    any of them
}