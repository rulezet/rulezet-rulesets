rule TTP_XOR_WriteProcessMemory_a115 {
  strings:
    $key_a115 = { f6 67 [2] c4 45 [2] c2 70 [2] ec 70 [2] d3 6c }

  condition:
    any of them
}