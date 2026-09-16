rule TTP_XOR_WriteProcessMemory_9ef2 {
  strings:
    $key_9ef2 = { c9 80 [2] fb a2 [2] fd 97 [2] d3 97 [2] ec 8b }

  condition:
    any of them
}