rule TTP_XOR_WriteProcessMemory_9ef0 {
  strings:
    $key_9ef0 = { c9 82 [2] fb a0 [2] fd 95 [2] d3 95 [2] ec 89 }

  condition:
    any of them
}