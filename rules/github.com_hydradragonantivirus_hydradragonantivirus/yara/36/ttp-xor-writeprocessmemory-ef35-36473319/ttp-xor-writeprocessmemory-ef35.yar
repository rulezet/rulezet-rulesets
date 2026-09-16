rule TTP_XOR_WriteProcessMemory_ef35 {
  strings:
    $key_ef35 = { b8 47 [2] 8a 65 [2] 8c 50 [2] a2 50 [2] 9d 4c }

  condition:
    any of them
}