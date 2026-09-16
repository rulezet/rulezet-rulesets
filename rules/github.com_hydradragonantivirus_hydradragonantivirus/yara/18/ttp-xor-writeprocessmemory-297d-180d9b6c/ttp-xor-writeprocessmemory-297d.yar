rule TTP_XOR_WriteProcessMemory_297d {
  strings:
    $key_297d = { 7e 0f [2] 4c 2d [2] 4a 18 [2] 64 18 [2] 5b 04 }

  condition:
    any of them
}