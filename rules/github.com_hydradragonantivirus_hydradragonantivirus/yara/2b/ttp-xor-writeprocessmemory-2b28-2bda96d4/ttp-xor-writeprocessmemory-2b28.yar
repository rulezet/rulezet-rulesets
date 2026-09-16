rule TTP_XOR_WriteProcessMemory_2b28 {
  strings:
    $key_2b28 = { 7c 5a [2] 4e 78 [2] 48 4d [2] 66 4d [2] 59 51 }

  condition:
    any of them
}