rule TTP_XOR_WriteProcessMemory_e27d {
  strings:
    $key_e27d = { b5 0f [2] 87 2d [2] 81 18 [2] af 18 [2] 90 04 }

  condition:
    any of them
}