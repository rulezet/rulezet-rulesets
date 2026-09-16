rule TTP_XOR_WriteProcessMemory_0411 {
  strings:
    $key_0411 = { 53 63 [2] 61 41 [2] 67 74 [2] 49 74 [2] 76 68 }

  condition:
    any of them
}