rule TTP_XOR_WriteProcessMemory_d56d {
  strings:
    $key_d56d = { 82 1f [2] b0 3d [2] b6 08 [2] 98 08 [2] a7 14 }

  condition:
    any of them
}