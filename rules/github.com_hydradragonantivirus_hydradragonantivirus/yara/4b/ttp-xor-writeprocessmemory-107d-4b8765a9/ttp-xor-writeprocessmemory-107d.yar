rule TTP_XOR_WriteProcessMemory_107d {
  strings:
    $key_107d = { 47 0f [2] 75 2d [2] 73 18 [2] 5d 18 [2] 62 04 }

  condition:
    any of them
}