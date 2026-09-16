rule TTP_XOR_WriteProcessMemory_ef28 {
  strings:
    $key_ef28 = { b8 5a [2] 8a 78 [2] 8c 4d [2] a2 4d [2] 9d 51 }

  condition:
    any of them
}