rule TTP_XOR_WriteProcessMemory_0c08 {
  strings:
    $key_0c08 = { 5b 7a [2] 69 58 [2] 6f 6d [2] 41 6d [2] 7e 71 }

  condition:
    any of them
}