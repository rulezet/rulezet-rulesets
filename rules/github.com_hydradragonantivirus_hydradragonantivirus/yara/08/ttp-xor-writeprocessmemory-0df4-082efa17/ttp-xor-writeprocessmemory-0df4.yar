rule TTP_XOR_WriteProcessMemory_0df4 {
  strings:
    $key_0df4 = { 5a 86 [2] 68 a4 [2] 6e 91 [2] 40 91 [2] 7f 8d }

  condition:
    any of them
}