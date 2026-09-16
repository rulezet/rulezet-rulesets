rule TTP_XOR_WriteProcessMemory_787d {
  strings:
    $key_787d = { 2f 0f [2] 1d 2d [2] 1b 18 [2] 35 18 [2] 0a 04 }

  condition:
    any of them
}