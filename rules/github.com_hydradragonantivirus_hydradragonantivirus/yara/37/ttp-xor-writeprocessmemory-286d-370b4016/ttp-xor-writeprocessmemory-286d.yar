rule TTP_XOR_WriteProcessMemory_286d {
  strings:
    $key_286d = { 7f 1f [2] 4d 3d [2] 4b 08 [2] 65 08 [2] 5a 14 }

  condition:
    any of them
}