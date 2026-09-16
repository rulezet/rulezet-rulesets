rule TTP_XOR_WriteProcessMemory_797d {
  strings:
    $key_797d = { 2e 0f [2] 1c 2d [2] 1a 18 [2] 34 18 [2] 0b 04 }

  condition:
    any of them
}