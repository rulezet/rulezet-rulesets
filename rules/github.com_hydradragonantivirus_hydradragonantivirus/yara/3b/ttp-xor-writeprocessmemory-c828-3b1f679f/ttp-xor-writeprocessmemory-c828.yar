rule TTP_XOR_WriteProcessMemory_c828 {
  strings:
    $key_c828 = { 9f 5a [2] ad 78 [2] ab 4d [2] 85 4d [2] ba 51 }

  condition:
    any of them
}