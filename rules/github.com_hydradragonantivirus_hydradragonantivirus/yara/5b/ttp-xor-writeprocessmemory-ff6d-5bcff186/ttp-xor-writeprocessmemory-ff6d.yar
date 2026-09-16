rule TTP_XOR_WriteProcessMemory_ff6d {
  strings:
    $key_ff6d = { a8 1f [2] 9a 3d [2] 9c 08 [2] b2 08 [2] 8d 14 }

  condition:
    any of them
}