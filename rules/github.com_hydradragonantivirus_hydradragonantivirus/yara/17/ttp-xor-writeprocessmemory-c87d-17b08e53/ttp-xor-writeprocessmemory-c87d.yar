rule TTP_XOR_WriteProcessMemory_c87d {
  strings:
    $key_c87d = { 9f 0f [2] ad 2d [2] ab 18 [2] 85 18 [2] ba 04 }

  condition:
    any of them
}