rule TTP_XOR_WriteProcessMemory_ef24 {
  strings:
    $key_ef24 = { b8 56 [2] 8a 74 [2] 8c 41 [2] a2 41 [2] 9d 5d }

  condition:
    any of them
}