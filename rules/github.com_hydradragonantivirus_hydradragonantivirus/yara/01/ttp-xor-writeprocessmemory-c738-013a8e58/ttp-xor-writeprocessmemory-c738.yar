rule TTP_XOR_WriteProcessMemory_c738 {
  strings:
    $key_c738 = { 90 4a [2] a2 68 [2] a4 5d [2] 8a 5d [2] b5 41 }

  condition:
    any of them
}