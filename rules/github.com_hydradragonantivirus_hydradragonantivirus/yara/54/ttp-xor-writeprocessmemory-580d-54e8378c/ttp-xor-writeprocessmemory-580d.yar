rule TTP_XOR_WriteProcessMemory_580d {
  strings:
    $key_580d = { 0f 7f [2] 3d 5d [2] 3b 68 [2] 15 68 [2] 2a 74 }

  condition:
    any of them
}