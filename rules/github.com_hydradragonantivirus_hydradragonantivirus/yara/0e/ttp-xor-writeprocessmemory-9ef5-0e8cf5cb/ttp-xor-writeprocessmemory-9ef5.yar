rule TTP_XOR_WriteProcessMemory_9ef5 {
  strings:
    $key_9ef5 = { c9 87 [2] fb a5 [2] fd 90 [2] d3 90 [2] ec 8c }

  condition:
    any of them
}