rule TTP_XOR_WriteProcessMemory_e41a {
  strings:
    $key_e41a = { b3 68 [2] 81 4a [2] 87 7f [2] a9 7f [2] 96 63 }

  condition:
    any of them
}