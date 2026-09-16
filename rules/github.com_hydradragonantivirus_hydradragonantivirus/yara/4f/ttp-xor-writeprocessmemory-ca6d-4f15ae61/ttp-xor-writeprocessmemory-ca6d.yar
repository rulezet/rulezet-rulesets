rule TTP_XOR_WriteProcessMemory_ca6d {
  strings:
    $key_ca6d = { 9d 1f [2] af 3d [2] a9 08 [2] 87 08 [2] b8 14 }

  condition:
    any of them
}