rule TTP_XOR_WriteProcessMemory_ef67 {
  strings:
    $key_ef67 = { b8 15 [2] 8a 37 [2] 8c 02 [2] a2 02 [2] 9d 1e }

  condition:
    any of them
}