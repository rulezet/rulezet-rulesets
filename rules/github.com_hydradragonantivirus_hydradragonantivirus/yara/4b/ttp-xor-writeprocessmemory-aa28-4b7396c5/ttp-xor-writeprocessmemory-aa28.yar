rule TTP_XOR_WriteProcessMemory_aa28 {
  strings:
    $key_aa28 = { fd 5a [2] cf 78 [2] c9 4d [2] e7 4d [2] d8 51 }

  condition:
    any of them
}