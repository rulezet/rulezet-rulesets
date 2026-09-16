rule TTP_XOR_WriteProcessMemory_9ef6 {
  strings:
    $key_9ef6 = { c9 84 [2] fb a6 [2] fd 93 [2] d3 93 [2] ec 8f }

  condition:
    any of them
}