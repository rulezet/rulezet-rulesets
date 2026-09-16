rule TTP_XOR_WriteProcessMemory_c628 {
  strings:
    $key_c628 = { 91 5a [2] a3 78 [2] a5 4d [2] 8b 4d [2] b4 51 }

  condition:
    any of them
}