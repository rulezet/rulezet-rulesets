rule TTP_XOR_WriteProcessMemory_b056 {
  strings:
    $key_b056 = { e7 24 [2] d5 06 [2] d3 33 [2] fd 33 [2] c2 2f }

  condition:
    any of them
}