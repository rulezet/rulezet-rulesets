rule TTP_XOR_WriteProcessMemory_ef23 {
  strings:
    $key_ef23 = { b8 51 [2] 8a 73 [2] 8c 46 [2] a2 46 [2] 9d 5a }

  condition:
    any of them
}