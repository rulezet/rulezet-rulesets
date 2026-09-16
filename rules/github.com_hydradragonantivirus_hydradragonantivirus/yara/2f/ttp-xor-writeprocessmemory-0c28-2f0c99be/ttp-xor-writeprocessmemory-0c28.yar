rule TTP_XOR_WriteProcessMemory_0c28 {
  strings:
    $key_0c28 = { 5b 5a [2] 69 78 [2] 6f 4d [2] 41 4d [2] 7e 51 }

  condition:
    any of them
}