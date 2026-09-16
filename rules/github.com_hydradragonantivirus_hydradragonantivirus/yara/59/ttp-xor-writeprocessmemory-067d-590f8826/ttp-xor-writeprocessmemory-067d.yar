rule TTP_XOR_WriteProcessMemory_067d {
  strings:
    $key_067d = { 51 0f [2] 63 2d [2] 65 18 [2] 4b 18 [2] 74 04 }

  condition:
    any of them
}