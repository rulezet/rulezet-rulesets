rule TTP_XOR_WriteProcessMemory_677d {
  strings:
    $key_677d = { 30 0f [2] 02 2d [2] 04 18 [2] 2a 18 [2] 15 04 }

  condition:
    any of them
}