rule TTP_XOR_WriteProcessMemory_381c {
  strings:
    $key_381c = { 6f 6e [2] 5d 4c [2] 5b 79 [2] 75 79 [2] 4a 65 }

  condition:
    any of them
}