rule TTP_XOR_WriteProcessMemory_b037 {
  strings:
    $key_b037 = { e7 45 [2] d5 67 [2] d3 52 [2] fd 52 [2] c2 4e }

  condition:
    any of them
}