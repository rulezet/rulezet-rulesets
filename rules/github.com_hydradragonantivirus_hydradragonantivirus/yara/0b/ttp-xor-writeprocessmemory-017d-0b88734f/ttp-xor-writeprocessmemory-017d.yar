rule TTP_XOR_WriteProcessMemory_017d {
  strings:
    $key_017d = { 56 0f [2] 64 2d [2] 62 18 [2] 4c 18 [2] 73 04 }

  condition:
    any of them
}