rule TTP_XOR_WriteProcessMemory_e128 {
  strings:
    $key_e128 = { b6 5a [2] 84 78 [2] 82 4d [2] ac 4d [2] 93 51 }

  condition:
    any of them
}