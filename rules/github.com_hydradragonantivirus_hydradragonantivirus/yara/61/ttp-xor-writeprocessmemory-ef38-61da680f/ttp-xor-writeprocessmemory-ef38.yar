rule TTP_XOR_WriteProcessMemory_ef38 {
  strings:
    $key_ef38 = { b8 4a [2] 8a 68 [2] 8c 5d [2] a2 5d [2] 9d 41 }

  condition:
    any of them
}