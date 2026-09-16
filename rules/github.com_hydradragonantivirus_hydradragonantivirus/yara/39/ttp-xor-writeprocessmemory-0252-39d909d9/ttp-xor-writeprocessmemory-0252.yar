rule TTP_XOR_WriteProcessMemory_0252 {
  strings:
    $key_0252 = { 55 20 [2] 67 02 [2] 61 37 [2] 4f 37 [2] 70 2b }

  condition:
    any of them
}