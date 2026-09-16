rule TTP_XOR_WriteProcessMemory_ff4f {
  strings:
    $key_ff4f = { a8 3d [2] 9a 1f [2] 9c 2a [2] b2 2a [2] 8d 36 }

  condition:
    any of them
}