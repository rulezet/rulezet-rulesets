rule TTP_XOR_WriteProcessMemory_b215 {
  strings:
    $key_b215 = { e5 67 [2] d7 45 [2] d1 70 [2] ff 70 [2] c0 6c }

  condition:
    any of them
}