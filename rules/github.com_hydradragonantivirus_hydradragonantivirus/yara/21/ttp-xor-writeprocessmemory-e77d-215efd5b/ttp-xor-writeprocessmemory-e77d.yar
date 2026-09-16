rule TTP_XOR_WriteProcessMemory_e77d {
  strings:
    $key_e77d = { b0 0f [2] 82 2d [2] 84 18 [2] aa 18 [2] 95 04 }

  condition:
    any of them
}