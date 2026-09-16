rule TTP_XOR_WriteProcessMemory_f57d {
  strings:
    $key_f57d = { a2 0f [2] 90 2d [2] 96 18 [2] b8 18 [2] 87 04 }

  condition:
    any of them
}