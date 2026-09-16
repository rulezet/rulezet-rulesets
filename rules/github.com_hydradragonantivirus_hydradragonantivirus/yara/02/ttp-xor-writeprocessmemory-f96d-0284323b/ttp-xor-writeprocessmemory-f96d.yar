rule TTP_XOR_WriteProcessMemory_f96d {
  strings:
    $key_f96d = { ae 1f [2] 9c 3d [2] 9a 08 [2] b4 08 [2] 8b 14 }

  condition:
    any of them
}