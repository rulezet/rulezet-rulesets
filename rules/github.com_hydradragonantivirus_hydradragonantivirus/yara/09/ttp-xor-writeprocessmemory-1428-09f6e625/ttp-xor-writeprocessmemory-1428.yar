rule TTP_XOR_WriteProcessMemory_1428 {
  strings:
    $key_1428 = { 43 5a [2] 71 78 [2] 77 4d [2] 59 4d [2] 66 51 }

  condition:
    any of them
}