rule TTP_XOR_WriteProcessMemory_9ef7 {
  strings:
    $key_9ef7 = { c9 85 [2] fb a7 [2] fd 92 [2] d3 92 [2] ec 8e }

  condition:
    any of them
}