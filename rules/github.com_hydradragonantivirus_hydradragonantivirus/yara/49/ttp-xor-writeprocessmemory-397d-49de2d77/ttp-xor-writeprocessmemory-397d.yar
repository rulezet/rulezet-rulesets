rule TTP_XOR_WriteProcessMemory_397d {
  strings:
    $key_397d = { 6e 0f [2] 5c 2d [2] 5a 18 [2] 74 18 [2] 4b 04 }

  condition:
    any of them
}