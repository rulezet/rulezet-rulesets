rule TTP_XOR_WriteProcessMemory_f56d {
  strings:
    $key_f56d = { a2 1f [2] 90 3d [2] 96 08 [2] b8 08 [2] 87 14 }

  condition:
    any of them
}